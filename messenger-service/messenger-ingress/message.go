package main

import (
	"errors"
	"strings"
	"time"
)

var (
	// ErrEmptyDestination indicates that a destination was not provided.
	ErrEmptyDestination = errors.New("destination is required")
	// ErrUnknownDestination indicates that the requested destination is not supported.
	ErrUnknownDestination = errors.New("destination is not supported")
	// ErrEmptyUserID indicates that the user identifier is missing.
	ErrEmptyUserID = errors.New("userId is required")
	// ErrEmptyText indicates that the text body is missing.
	ErrEmptyText = errors.New("text is required")
)

// Message represents a canonical message that can be delivered to downstream messengers.
type Message struct {
	Destination string
	UserID      string
	Text        string
	ReceivedAt  time.Time
}

// NewMessage validates raw input and constructs a Message.
func NewMessage(destination, userID, text string, receivedAt time.Time) (Message, error) {
	dest := strings.TrimSpace(destination)
	if dest == "" {
		return Message{}, ErrEmptyDestination
	}

	uid := strings.TrimSpace(userID)
	if uid == "" {
		return Message{}, ErrEmptyUserID
	}

	body := strings.TrimSpace(text)
	if body == "" {
		return Message{}, ErrEmptyText
	}

	ts := receivedAt
	if ts.IsZero() {
		ts = time.Now().UTC()
	} else {
		ts = ts.UTC()
	}

	return Message{
		Destination: dest,
		UserID:      uid,
		Text:        body,
		ReceivedAt:  ts,
	}, nil
}
