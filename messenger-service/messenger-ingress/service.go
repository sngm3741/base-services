package main

import (
	"context"
	"strings"
	"time"
)

// MessageService validates and dispatches outgoing messages.
type MessageService struct {
	publisher          *Publisher
	defaultDestination string
	now                func() time.Time
}

// NewMessageService builds a MessageService with sane defaults.
func NewMessageService(pub *Publisher, defaultDestination string) *MessageService {
	return &MessageService{
		publisher:          pub,
		defaultDestination: strings.TrimSpace(defaultDestination),
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

// Send validates the message payload and forwards it to the publisher.
func (s *MessageService) Send(ctx context.Context, destination, userID, text string) error {
	dest := strings.TrimSpace(destination)
	if dest == "" {
		dest = s.defaultDestination
	}

	message, err := NewMessage(dest, userID, text, s.now())
	if err != nil {
		return err
	}

	return s.publisher.Publish(ctx, message)
}

// WithNow allows tests to override the clock.
func (s *MessageService) WithNow(now func() time.Time) {
	if now == nil {
		return
	}
	s.now = now
}
