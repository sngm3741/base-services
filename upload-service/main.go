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
	logger := log.New(os.Stdout, "[media-service] ", log.LstdFlags|log.Lmsgprefix)
	cfg := LoadConfig()

	if err := cfg.Validate(); err != nil {
		logger.Fatalf("config error: %v", err)
	}

	storage, err := NewStorage(r2Context(), cfg)
	fatalIfErr(logger, "failed to init storage", err)

	srv := NewServer(cfg, storage, logger)
	router := NewRouter(srv)

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Printf("listening on %s", cfg.HTTPAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server error: %v", err)
		}
	}()

	<-done
	logger.Println("shutting down...")

	shutdownCtx, cancel := timeoutContext(10 * time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
}

func timeoutContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func r2Context() context.Context {
	return context.Background()
}
