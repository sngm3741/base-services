// LINE専用Webhookサーバー。Messaging APIのイベントを受け取り、NATSに中継する。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nats-io/nats.go"
)

const (
	defaultNATSURL     = "nats://nats:4222"
	defaultLineSubject = "line.events"
	defaultHTTPAddress = ":8080"
	maxBodySize        = int64(1 << 20) // 1MBまで許可
	retryCount         = 10
)

var errLineNoEvents = errors.New("line: eventsが空です")
var jst = time.FixedZone("JST", 9*60*60)

// lineMessagePayload はLINEイベントを標準化した中間フォーマット。
type lineMessagePayload struct {
	Destination string          `json:"destination"`
	EventType   string          `json:"eventType"`
	UserID      string          `json:"userId"`
	Message     json.RawMessage `json:"message,omitempty"`
	ReceivedAt  time.Time       `json:"receivedAt"`
}

// lineEventsRequest はLINE Messaging APIのWebhook JSONの一部。
type lineEventsRequest struct {
	Destination string `json:"destination"`
	Events      []struct {
		Type       string `json:"type"`
		ReplyToken string `json:"replyToken"`
		Message    *struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"message"`
		Source struct {
			Type   string `json:"type"`
			UserID string `json:"userId"`
		} `json:"source"`
	} `json:"events"`
}

// main は環境変数を元に LINE Webhook サーバーを起動します。
func main() {
	cfg := loadConfig()

	nc, err := connectLINE(cfg.natsURL)
	if err != nil {
		log.Fatalf("LINE用NATS接続に失敗: %v", err)
	}
	defer nc.Drain()

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)

	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"date":   time.Now().In(jst).Format(time.RFC3339),
		})
	})

	router.Post("/message/webhook", lineWebhookHandler(nc, cfg.lineSubject))

	srv := &http.Server{
		Addr:    cfg.httpAddress,
		Handler: router,
	}

	log.Printf("LINE Webhookサーバー起動: http://localhost%v/webhook", cfg.httpAddress)

	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("サーバーエラー: %v", err)
	}
}

// lineWebhookHandler は LINE Webhook の HTTP リクエストを処理し、NATS へイベントを転送します。
func lineWebhookHandler(nc *nats.Conn, subj string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
		if err != nil {
			http.Error(w, "ボディの読み取りに失敗", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		log.Printf("LINE受信ボディ: %s", string(body))

		payload, err := parseLINEPayload(body)
		if err != nil {
			if errors.Is(err, errLineNoEvents) {
				log.Println("LINEイベントなし: 検証リクエストを受信")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
				return
			}

			log.Printf("LINEイベント解析失敗: %v", err)
			http.Error(w, "イベント解析に失敗", http.StatusBadRequest)
			return
		}

		msg, err := json.Marshal(payload)
		if err != nil {
			log.Printf("LINE payloadエンコード失敗: %v", err)
			http.Error(w, "内部エラー", http.StatusInternalServerError)
			return
		}

		if err := nc.Publish(subj, msg); err != nil {
			log.Printf("LINE NATS Publish失敗: %v", err)
			http.Error(w, "NATS送信に失敗", http.StatusBadGateway)
			return
		}

		if err := nc.FlushTimeout(5 * time.Second); err != nil {
			log.Printf("LINE NATS Flush失敗: %v", err)
			http.Error(w, "NATS同期に失敗", http.StatusGatewayTimeout)
			return
		}

		log.Printf("LINEイベントをNATSへ転送: destination=%s user=%s", payload.Destination, payload.UserID)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}
}

// parseLINEPayload は LINE から届いた JSON ボディを標準化されたペイロードへ変換します。
func parseLINEPayload(body []byte) (*lineMessagePayload, error) {
	var req lineEventsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	if len(req.Events) == 0 {
		return nil, errLineNoEvents
	}

	evt := req.Events[0]
	payload := &lineMessagePayload{
		Destination: req.Destination,
		EventType:   evt.Type,
		UserID:      evt.Source.UserID,
		ReceivedAt:  time.Now(),
	}

	switch evt.Type {
	case "message":
		if evt.Message == nil {
			return nil, errors.New("messageイベントだが本文がありません")
		}
		msg := map[string]string{
			"message": evt.Message.Text,
		}
		msgJSON, err := json.Marshal(msg)
		if err != nil {
			return nil, fmt.Errorf("messageエンコードに失敗: %w", err)
		}
		payload.Message = json.RawMessage(msgJSON)
		log.Printf("LINE messageイベント解析: user=%s text=%s", evt.Source.UserID, evt.Message.Text)
	case "follow":
		log.Printf("LINE followイベント受信: user=%s", evt.Source.UserID)
	default:
		log.Printf("LINE未対応イベント: type=%s user=%s", evt.Type, evt.Source.UserID)
	}

	return payload, nil
}

// connectLINE は NATS への接続を一定回数リトライしながら確立します。
func connectLINE(natsURL string) (*nats.Conn, error) {
	var lastErr error
	for i := range retryCount {
		nc, err := nats.Connect(natsURL, nats.MaxReconnects(0))
		if err == nil {
			log.Printf("LINE用NATSに接続: %s", natsURL)
			return nc, nil
		}

		lastErr = err
		log.Printf("LINE用NATS接続失敗(%d/%d): %v", i+1, retryCount, err)
		time.Sleep(500 * time.Millisecond)
	}

	return nil, fmt.Errorf("LINE NATS接続失敗: %w", lastErr)
}

// config は Webhook アプリケーションで利用する環境設定を保持します。
type config struct {
	natsURL     string
	lineSubject string
	httpAddress string
}

// loadConfig は環境変数を読み取って config を構築します。
func loadConfig() config {
	return config{
		natsURL:     getEnvFirst([]string{"NATS_URL"}, defaultNATSURL),
		lineSubject: getEnvFirst([]string{"MESSENGER_LINE_EVENTS_SUBJECT", "LINE_EVENTS_SUBJECT"}, defaultLineSubject),
		httpAddress: getEnvFirst([]string{"MESSENGER_LINE_HTTP_ADDR", "LINE_HTTP_ADDR"}, defaultHTTPAddress),
	}
}

// getEnvFirst は優先順位付きの環境変数から最初に見つかった値を返します。
func getEnvFirst(keys []string, fallback string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return fallback
}
