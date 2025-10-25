package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr          string
	ChannelID         string
	ChannelSecret     string
	RedirectURI       string
	Scopes            []string
	StateSecret       []byte
	StateTTL          time.Duration
	AllowedOrigins    map[string]struct{}
	JWTSecret         []byte
	JWTIssuer         string
	JWTAudience       string
	JWTExpiresIn      time.Duration
	AuthorizeEndpoint string
	TokenEndpoint     string
	ProfileEndpoint   string
	BotPrompt         string
	HTTPTimeout       time.Duration
}

func LoadConfig() (Config, error) {
	cfg := Config{
		HTTPAddr:          getEnvOrDefault("AUTH_LINE_HTTP_ADDR", ":8080"),
		ChannelID:         strings.TrimSpace(os.Getenv("AUTH_LINE_CHANNEL_ID")),
		ChannelSecret:     strings.TrimSpace(os.Getenv("AUTH_LINE_CHANNEL_SECRET")),
		RedirectURI:       strings.TrimSpace(os.Getenv("AUTH_LINE_REDIRECT_URI")),
		Scopes:            parseList("AUTH_LINE_SCOPES", []string{"profile", "openid"}),
		StateSecret:       []byte(strings.TrimSpace(os.Getenv("AUTH_LINE_STATE_SECRET"))),
		StateTTL:          parseDuration("AUTH_LINE_STATE_TTL", 10*time.Minute),
		AllowedOrigins:    parseOrigins("AUTH_LINE_ALLOWED_ORIGINS"),
		JWTSecret:         []byte(strings.TrimSpace(os.Getenv("AUTH_LINE_JWT_SECRET"))),
		JWTIssuer:         getEnvOrDefault("AUTH_LINE_JWT_ISSUER", "auth-line"),
		JWTAudience:       strings.TrimSpace(os.Getenv("AUTH_LINE_JWT_AUDIENCE")),
		JWTExpiresIn:      parseDuration("AUTH_LINE_JWT_EXPIRES_IN", 24*time.Hour),
		AuthorizeEndpoint: getEnvOrDefault("AUTH_LINE_AUTHORIZE_ENDPOINT", "https://access.line.me/oauth2/v2.1/authorize"),
		TokenEndpoint:     getEnvOrDefault("AUTH_LINE_TOKEN_ENDPOINT", "https://api.line.me/oauth2/v2.1/token"),
		ProfileEndpoint:   getEnvOrDefault("AUTH_LINE_PROFILE_ENDPOINT", "https://api.line.me/v2/profile"),
		BotPrompt:         getEnvOrDefault("AUTH_LINE_BOT_PROMPT", ""),
		HTTPTimeout:       parseDuration("AUTH_LINE_HTTP_TIMEOUT", 10*time.Second),
	}

	if cfg.ChannelID == "" {
		return Config{}, fmt.Errorf("AUTH_LINE_CHANNEL_ID is required")
	}
	if cfg.ChannelSecret == "" {
		return Config{}, fmt.Errorf("AUTH_LINE_CHANNEL_SECRET is required")
	}
	if cfg.RedirectURI == "" {
		return Config{}, fmt.Errorf("AUTH_LINE_REDIRECT_URI is required")
	}
	if len(cfg.StateSecret) == 0 {
		return Config{}, fmt.Errorf("AUTH_LINE_STATE_SECRET is required")
	}
	if len(cfg.JWTSecret) == 0 {
		return Config{}, fmt.Errorf("AUTH_LINE_JWT_SECRET is required")
	}
	if cfg.StateTTL <= 0 {
		return Config{}, fmt.Errorf("AUTH_LINE_STATE_TTL must be positive")
	}
	if cfg.JWTExpiresIn <= 0 {
		return Config{}, fmt.Errorf("AUTH_LINE_JWT_EXPIRES_IN must be positive")
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}

	return cfg, nil
}

func getEnvOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseList(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return fallback
	}
	return values
}

func parseOrigins(key string) map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return map[string]struct{}{}
	}
	parts := strings.Split(raw, ",")
	origins := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			origins[trimmed] = struct{}{}
		}
	}
	return origins
}

func parseDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	duration, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return duration
}
