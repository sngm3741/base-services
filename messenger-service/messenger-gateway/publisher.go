package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

const defaultPublishTimeout = 2 * time.Second

// Publisher sends messages to NATS subjects based on their destination.
type Publisher struct {
	conn     *nats.Conn
	subjects map[string]string
	logger   *log.Logger
}

// NewPublisher constructs a Publisher instance.
func NewPublisher(conn *nats.Conn, subjects map[string]string, logger *log.Logger) *Publisher {
	copied := make(map[string]string, len(subjects))
	for key, value := range subjects {
		if key == "" || value == "" {
			continue
		}
		copied[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}

	return &Publisher{
		conn:     conn,
		subjects: copied,
		logger:   logger,
	}
}

// Publish encodes and publishes the message to the appropriate NATS subject.
func (p *Publisher) Publish(ctx context.Context, message Message) error {
	subject, ok := p.subjects[message.Destination]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownDestination, message.Destination)
	}

	payload, err := encodePayload(message)
	if err != nil {
		return err
	}

	if err := p.conn.Publish(subject, payload); err != nil {
		return fmt.Errorf("nats publish failed: %w", err)
	}

	if err := p.conn.FlushTimeout(p.publishTimeout(ctx)); err != nil {
		return fmt.Errorf("nats flush failed: %w", err)
	}

	if p.logger != nil {
		p.logger.Printf("published message: destination=%s subject=%s userId=%s", message.Destination, subject, message.UserID)
	}

	return nil
}

func (p *Publisher) publishTimeout(ctx context.Context) time.Duration {
	if ctx == nil {
		return defaultPublishTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			return remaining
		}
	}
	return defaultPublishTimeout
}

func encodePayload(message Message) ([]byte, error) {
	body, err := json.Marshal(map[string]string{
		"message": message.Text,
	})
	if err != nil {
		return nil, fmt.Errorf("encode body failed: %w", err)
	}

	envelope := struct {
		Destination string          `json:"destination"`
		UserID      string          `json:"userId"`
		Message     json.RawMessage `json:"message"`
		ReceivedAt  time.Time       `json:"receivedAt"`
	}{
		Destination: message.Destination,
		UserID:      message.UserID,
		Message:     json.RawMessage(body),
		ReceivedAt:  message.ReceivedAt,
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode envelope failed: %w", err)
	}
	return data, nil
}
