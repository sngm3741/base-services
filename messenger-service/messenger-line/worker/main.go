// LINE宛メッセージ処理ワーカー。messenger-line-webhookから流れてきたイベントを受信し、LINE Messaging APIへプッシュ送信する。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	defaultNATSURL          = "nats://nats:4222"
	defaultLineSubject      = "line.events"
	defaultLinePushEndpoint = "https://api.line.me/v2/bot/message/push"
	maxConnectRetry         = 10

	welcomeText = "友だち追加ありがとうございます！アンケート投稿はマイページからどうぞ。分からないことがあれば気軽に聞いてくださいね。"
)

// linePayload は messenger-line-webhook から流れてくるメッセージ形式。
type linePayload struct {
	Destination string          `json:"destination"`
	EventType   string          `json:"eventType"`
	UserID      string          `json:"userId"`
	Message     json.RawMessage `json:"message"`
	ReceivedAt  time.Time       `json:"receivedAt"`
}

// main は LINE ワーカーを起動し、NATS からイベントを購読します。
func main() {
	log.Printf("開始時刻: %s", time.Now().Format("2006-01-02 15:04:05"))

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("設定の読み込みに失敗: %v", err)
	}

	conn, err := connect(cfg.natsURL)
	if err != nil {
		log.Fatalf("NATS接続に失敗: %v", err)
	}
	defer conn.Drain()

	client := &http.Client{Timeout: 5 * time.Second}

	_, err = conn.Subscribe(cfg.lineSubject, func(msg *nats.Msg) {
		if err := handleMessage(msg.Data, cfg, client); err != nil {
			log.Printf("処理エラー: %v", err)
		}
	})
	if err != nil {
		log.Fatalf("購読に失敗: %v", err)
	}

	if err := conn.Flush(); err != nil {
		log.Fatalf("購読登録の同期に失敗: %v", err)
	}

	log.Printf("サブジェクト %q の受信待機を開始", cfg.lineSubject)

	select {} // コンテナを終了させない
}

// handleMessage は NATS から受信したデータをデコードし、LINE 送信までを制御します。
func handleMessage(data []byte, cfg config, client *http.Client) error {
	var payload linePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("payloadのJSONデコードに失敗: %w", err)
	}

	log.Printf("LINEイベント受信: destination=%s type=%s user=%s message=%s", payload.Destination, payload.EventType, payload.UserID, string(payload.Message))

	switch payload.EventType {
	case "follow":
		return deliverToLine(payload.UserID, welcomeMessage(), cfg, client)
	case "message":
		text, err := extractMessageText(payload.Message)
		if err != nil {
			return fmt.Errorf("本文抽出に失敗: %w", err)
		}
		return deliverToLine(payload.UserID, text, cfg, client)
	default:
		log.Printf("未対応イベント種別のためスキップ: type=%s user=%s", payload.EventType, payload.UserID)
		return nil
	}
}

func welcomeMessage() string {
	return welcomeText
}

// extractMessageText は Webhook ペイロードから送信本文を取り出します。
func extractMessageText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("messageが空です")
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", err
	}
	if body.Message == "" {
		return "", errors.New("messageフィールドが空です")
	}

	return body.Message, nil
}

// deliverToLine は LINE Messaging API へ push メッセージを送信します。
func deliverToLine(userID, text string, cfg config, client *http.Client) error {
	if userID == "" {
		return errors.New("userIdが空です")
	}

	reqBody := map[string]any{
		"to": userID,
		"messages": []map[string]string{{
			"type": "text",
			"text": text,
		}},
	}

	b, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, cfg.linePushEndpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.lineChannelToken)

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("LINE APIエラー: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	log.Printf("LINEへ送信完了: to=%s text=%s", userID, text)
	return nil
}

// connect は NATS への接続を一定回数リトライします。
func connect(natsURL string) (*nats.Conn, error) {
	var lastErr error
	for i := range maxConnectRetry {
		conn, err := nats.Connect(natsURL, nats.MaxReconnects(0))
		if err == nil {
			log.Printf("NATSに接続: %s", natsURL)
			return conn, nil
		}

		lastErr = err
		log.Printf("接続失敗(%d/%d): %v", i+1, maxConnectRetry, err)
		time.Sleep(500 * time.Millisecond)
	}

	return nil, fmt.Errorf("%s への接続に失敗: %w", natsURL, lastErr)
}

// config はワーカー実行に必要な設定値をまとめます。
type config struct {
	natsURL          string
	lineSubject      string
	linePushEndpoint string
	lineChannelToken string
}

// loadConfig は環境変数から config を構築し、必須値を検証します。
func loadConfig() (config, error) {
	cfg := config{
		natsURL:          getEnvFirst([]string{"NATS_URL"}, defaultNATSURL),
		lineSubject:      getEnvFirst([]string{"MESSENGER_LINE_EVENTS_SUBJECT", "LINE_EVENTS_SUBJECT"}, defaultLineSubject),
		linePushEndpoint: getEnvFirst([]string{"MESSENGER_LINE_PUSH_ENDPOINT", "LINE_PUSH_ENDPOINT"}, defaultLinePushEndpoint),
		lineChannelToken: getEnvFirst([]string{"MESSENGER_LINE_CHANNEL_TOKEN", "LINE_CHANNEL_TOKEN"}, ""),
	}

	if cfg.lineChannelToken == "" {
		return config{}, errors.New("LINE_CHANNEL_TOKEN (または MESSENGER_LINE_CHANNEL_TOKEN) is required")
	}

	return cfg, nil
}

// getEnvFirst は優先順に環境変数を調べ、最初の値を返します。
func getEnvFirst(keys []string, fallback string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return fallback
}
