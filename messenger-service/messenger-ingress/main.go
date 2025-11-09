package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	natsConnectRetry    = 10
	natsConnectInterval = 500 * time.Millisecond
	httpShutdownTimeout = 5 * time.Second
)

func main() {
	cfg := LoadConfig()

	logger := log.New(os.Stdout, "[messenger-ingress] ", log.LstdFlags|log.Lmsgprefix)
	conn, err := connectNATS(cfg.NATSURL, logger)
	if err != nil {
		logger.Fatalf("failed to connect to NATS after retries: %v", err)
	}
	defer func() {
		if drainErr := conn.Drain(); drainErr != nil {
			logger.Printf("NATS 接続のドレインに失敗しました: %v", drainErr)
		}
	}()

	publisher := NewPublisher(conn, cfg.Subjects, logger)
	messageService := NewMessageService(publisher, cfg.DefaultDestination)
	router := NewRouter(messageService, logger, cfg.RequestTimeout)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Printf("HTTP サーバーを %s で待ち受けます", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("HTTP サーバーが異常終了しました: %v", err)
		}
	}()

	waitForShutdown(server, logger)
}

// connectNATS は NATS に複数回リトライしながら接続し、成功した接続を返します。
func connectNATS(url string, logger *log.Logger) (*nats.Conn, error) {
	var lastErr error
	for attempt := 1; attempt <= natsConnectRetry; attempt++ {
		conn, err := nats.Connect(url, nats.MaxReconnects(-1), nats.Name("messenger-ingress"))
		if err == nil {
			logger.Printf("NATS に接続しました: %s", url)
			return conn, nil
		}

		lastErr = err
		logger.Printf("NATS 接続リトライ (%d/%d) に失敗しました: %v", attempt, natsConnectRetry, err)
		time.Sleep(natsConnectInterval)
	}

	return nil, lastErr
}

// waitForShutdown は終了シグナルを待ち受け、Graceful Shutdown を実行します。
func waitForShutdown(server *http.Server, logger *log.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	<-sigCh
	logger.Println("終了シグナルを受信しました")

	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Printf("HTTP サーバーのシャットダウンでエラーが発生しました: %v", err)
	}

	logger.Println("シャットダウンシーケンスが完了しました")
}
