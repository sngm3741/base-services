package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

const maxRequestBody = 1 << 20 // 1 MiB

var jst = time.FixedZone("JST", 9*60*60)

// NewRouter wires HTTP routes to the provided message service.
func NewRouter(service *MessageService, logger *log.Logger, timeout time.Duration) http.Handler {
	h := &handler{
		service: service,
		logger:  logger,
		timeout: timeout,
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)

	router.Get("/healthz", h.health)
	router.Post("/api/messages", h.sendMessage)

	return router
}

type handler struct {
	service *MessageService
	logger  *log.Logger
	timeout time.Duration
}

func (h *handler) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"date":   time.Now().In(jst).Format(time.RFC3339),
	})
}

func (h *handler) sendMessage(w http.ResponseWriter, r *http.Request) {
	var body sendMessageRequest

	if err := decodeJSON(r.Context(), r.Body, &body); err != nil {
		h.logErr("invalid request body", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ctx, cancel := h.requestContext(r.Context())
	defer cancel()

	if err := h.service.Send(ctx, body.Destination, body.UserID, body.Text); err != nil {
		h.handleError(w, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "accepted",
	})
}

func (h *handler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEmptyDestination),
		errors.Is(err, ErrEmptyUserID),
		errors.Is(err, ErrEmptyText),
		errors.Is(err, ErrUnknownDestination):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		h.logErr("send message failed", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (h *handler) requestContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := h.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return context.WithTimeout(parent, timeout)
}

func decodeJSON(_ context.Context, reader io.ReadCloser, target any) error {
	defer reader.Close()

	limited := io.LimitReader(reader, maxRequestBody)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()

	return dec.Decode(target)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *handler) logErr(message string, err error) {
	if h.logger == nil {
		return
	}
	h.logger.Printf("%s: %v", message, err)
}

type sendMessageRequest struct {
	Destination string `json:"destination,omitempty"`
	UserID      string `json:"userId"`
	Text        string `json:"text"`
}
