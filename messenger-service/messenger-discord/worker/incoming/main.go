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
	defaultNATSURL           = "nats://nats:4222"
	defaultDiscordSubject    = "discord.incoming"
	defaultHTTPTimeout       = 5 * time.Second
	maxConnectRetry          = 10
	connectRetryInterval     = 500 * time.Millisecond
	defaultWebhookUsername   = "Makoto Club"
	maxDiscordContentLength  = 2000
	defaultAllowedMentionKey = "parse"
)

type gatewayPayload struct {
	Destination string          `json:"destination"`
	UserID      string          `json:"userId"`
	Message     json.RawMessage `json:"message"`
	ReceivedAt  time.Time       `json:"receivedAt"`
}

type messageBody struct {
	Message string `json:"message"`
}

type config struct {
	natsURL    string
	subject    string
	webhookURL string
	username   string
	avatarURL  string
	timeout    time.Duration
}

func main() {
	log.Printf("開始時刻: %s", time.Now().Format(time.RFC3339))

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("設定の読み込みに失敗: %v", err)
	}

	conn, err := connectNATS(cfg.natsURL)
	if err != nil {
		log.Fatalf("NATS接続に失敗: %v", err)
	}
	defer conn.Drain()

	client := &http.Client{Timeout: cfg.timeout}

	_, err = conn.Subscribe(cfg.subject, func(msg *nats.Msg) {
		if err := handleMessage(cfg, client, msg.Data); err != nil {
			log.Printf("処理エラー: %v", err)
		}
	})
	if err != nil {
		log.Fatalf("購読に失敗: %v", err)
	}

	if err := conn.Flush(); err != nil {
		log.Fatalf("購読登録の同期に失敗: %v", err)
	}

	log.Printf("サブジェクト %q の受信待機を開始", cfg.subject)
	select {}
}

func loadConfig() (config, error) {
	timeout := defaultHTTPTimeout
	if raw := strings.TrimSpace(os.Getenv("DISCORD_INCOMING_HTTP_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			timeout = parsed
		} else {
			log.Printf("WARN invalid DISCORD_INCOMING_HTTP_TIMEOUT=%s: %v. Using default %s", raw, err, defaultHTTPTimeout)
		}
	}

	cfg := config{
		natsURL:    firstEnv([]string{"NATS_URL"}, defaultNATSURL),
		subject:    firstEnv([]string{"MESSENGER_DISCORD_INCOMING_SUBJECT"}, defaultDiscordSubject),
		webhookURL: strings.TrimSpace(os.Getenv("DISCORD_INCOMING_WEBHOOK_URL")),
		username:   strings.TrimSpace(os.Getenv("DISCORD_INCOMING_USERNAME")),
		avatarURL:  strings.TrimSpace(os.Getenv("DISCORD_INCOMING_AVATAR_URL")),
		timeout:    timeout,
	}

	if cfg.webhookURL == "" {
		return config{}, errors.New("DISCORD_INCOMING_WEBHOOK_URL is required")
	}

	if cfg.username == "" {
		cfg.username = defaultWebhookUsername
	}

	return cfg, nil
}

func firstEnv(keys []string, fallback string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return fallback
}

func connectNATS(url string) (*nats.Conn, error) {
	var lastErr error
	for attempt := 1; attempt <= maxConnectRetry; attempt++ {
		conn, err := nats.Connect(url, nats.MaxReconnects(-1), nats.Name("messenger-discord-incoming-worker"))
		if err == nil {
			log.Printf("NATSに接続しました: %s", url)
			return conn, nil
		}

		lastErr = err
		log.Printf("NATS接続リトライ (%d/%d) に失敗: %v", attempt, maxConnectRetry, err)
		time.Sleep(connectRetryInterval)
	}

	return nil, lastErr
}

func handleMessage(cfg config, client *http.Client, data []byte) error {
	var payload gatewayPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("gatewayペイロードのパースに失敗: %w", err)
	}

	text, err := extractMessageText(payload.Message)
	if err != nil {
		return fmt.Errorf("本文抽出に失敗: %w", err)
	}

	if err := deliverToDiscord(cfg, client, text); err != nil {
		return fmt.Errorf("Discord送信に失敗: %w", err)
	}

	log.Printf("Discordへ送信完了: userId=%s length=%d", payload.UserID, len(text))
	return nil
}

func extractMessageText(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("message フィールドが空です")
	}

	var body messageBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return "", err
	}

	text := strings.TrimSpace(body.Message)
	if text == "" {
		return "", errors.New("message コンテンツが空です")
	}

	if len([]rune(text)) > maxDiscordContentLength {
		return "", fmt.Errorf("message が Discord の上限 %d 文字を超えています", maxDiscordContentLength)
	}

	return text, nil
}

func deliverToDiscord(cfg config, client *http.Client, text string) error {
	payload := map[string]any{
		"content": text,
		"allowed_mentions": map[string]any{
			defaultAllowedMentionKey: []string{},
		},
	}

	if cfg.username != "" {
		payload["username"] = cfg.username
	}
	if cfg.avatarURL != "" {
		payload["avatar_url"] = cfg.avatarURL
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("Discord送信用ペイロードの生成に失敗: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, cfg.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("Discord送信リクエストの作成に失敗: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Discord送信リクエストに失敗: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		message, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		return fmt.Errorf("Discord送信エラー: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(message)))
	}

	return nil
}
