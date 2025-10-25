package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidState = errors.New("invalid state")
	ErrStateExpired = errors.New("state expired")
)

type stateManager struct {
	secret []byte
	ttl    time.Duration
}

type statePayload struct {
	IssuedAt time.Time
	Origin   string
	Nonce    string
}

func newStateManager(secret []byte, ttl time.Duration) *stateManager {
	return &stateManager{
		secret: append([]byte(nil), secret...),
		ttl:    ttl,
	}
}

func (m *stateManager) issue(origin string) (string, *statePayload, error) {
	nonce, err := randomString(32)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	payload := &statePayload{
		IssuedAt: time.Now().UTC(),
		Origin:   origin,
		Nonce:    nonce,
	}

	serialized := fmt.Sprintf("%d|%s|%s", payload.IssuedAt.Unix(), origin, nonce)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(serialized))
	signature := mac.Sum(nil)

	state := fmt.Sprintf("%s|%s", serialized, base64.RawURLEncoding.EncodeToString(signature))
	return base64.RawURLEncoding.EncodeToString([]byte(state)), payload, nil
}

func (m *stateManager) verify(state string) (*statePayload, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return nil, ErrInvalidState
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return nil, ErrInvalidState
	}

	issuedAtRaw, origin, nonce, sigRaw := parts[0], parts[1], parts[2], parts[3]

	expected := fmt.Sprintf("%s|%s|%s", issuedAtRaw, origin, nonce)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(expected))
	expectedSig := mac.Sum(nil)

	providedSig, err := base64.RawURLEncoding.DecodeString(sigRaw)
	if err != nil {
		return nil, ErrInvalidState
	}

	if !hmac.Equal(providedSig, expectedSig) {
		return nil, ErrInvalidState
	}

	issuedUnix, err := parseUnix(issuedAtRaw)
	if err != nil {
		return nil, ErrInvalidState
	}
	issuedAt := time.Unix(issuedUnix, 0).UTC()

	if time.Since(issuedAt) > m.ttl {
		return nil, ErrStateExpired
	}

	return &statePayload{
		IssuedAt: issuedAt,
		Origin:   origin,
		Nonce:    nonce,
	}, nil
}

func randomString(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func parseUnix(value string) (int64, error) {
	var unix int64
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid unix timestamp")
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, err
	}
	unix = parsed
	return unix, nil
}
