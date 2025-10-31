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
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	logger := log.New(os.Stdout, "[auth-twitter] ", log.LstdFlags|log.Lmsgprefix)
	server := NewServer(cfg, logger)

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		logger.Printf("HTTP サーバーを %s で待ち受けます", cfg.HTTPAddr)
		errChan <- httpServer.ListenAndServe()
	}()

	waitForShutdown(httpServer, errChan, logger)
}

func waitForShutdown(httpServer *http.Server, errChan <-chan error, logger *log.Logger) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("HTTP サーバーが異常終了しました: %v", err)
		}
	case sig := <-sigChan:
		logger.Printf("シグナル %s を受信しました。シャットダウンを開始します。", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("HTTP サーバーのシャットダウンに失敗しました: %v", err)
	}
	logger.Println("シャットダウンが完了しました。")
}
