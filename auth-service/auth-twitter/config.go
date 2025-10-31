package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr              string
	ClientID              string
	ClientSecret          string
	RedirectURI           string
	Scopes                []string
	StateSecret           []byte
	StateTTL              time.Duration
	AllowedOrigins        map[string]struct{}
	JWTSecret             []byte
	JWTIssuer             string
	JWTAudience           string
	JWTExpiresIn          time.Duration
	AuthorizeEndpoint     string
	TokenEndpoint         string
	ProfileEndpoint       string
	HTTPTimeout           time.Duration
	RedirectPath          string
	DefaultRedirectOrigin string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		HTTPAddr:              getEnvOrDefault("AUTH_TWITTER_HTTP_ADDR", ":8080"),
		ClientID:              strings.TrimSpace(os.Getenv("AUTH_TWITTER_CLIENT_ID")),
		ClientSecret:          strings.TrimSpace(os.Getenv("AUTH_TWITTER_CLIENT_SECRET")),
		RedirectURI:           strings.TrimSpace(os.Getenv("AUTH_TWITTER_REDIRECT_URI")),
		Scopes:                parseList("AUTH_TWITTER_SCOPES", []string{"tweet.read", "users.read"}),
		StateSecret:           []byte(strings.TrimSpace(os.Getenv("AUTH_TWITTER_STATE_SECRET"))),
		StateTTL:              parseDuration("AUTH_TWITTER_STATE_TTL", 10*time.Minute),
		AllowedOrigins:        parseOrigins("AUTH_TWITTER_ALLOWED_ORIGINS"),
		JWTSecret:             []byte(strings.TrimSpace(os.Getenv("AUTH_TWITTER_JWT_SECRET"))),
		JWTIssuer:             getEnvOrDefault("AUTH_TWITTER_JWT_ISSUER", "auth-twitter"),
		JWTAudience:           strings.TrimSpace(os.Getenv("AUTH_TWITTER_JWT_AUDIENCE")),
		JWTExpiresIn:          parseDuration("AUTH_TWITTER_JWT_EXPIRES_IN", 24*time.Hour),
		AuthorizeEndpoint:     getEnvOrDefault("AUTH_TWITTER_AUTHORIZE_ENDPOINT", "https://twitter.com/i/oauth2/authorize"),
		TokenEndpoint:         getEnvOrDefault("AUTH_TWITTER_TOKEN_ENDPOINT", "https://api.twitter.com/2/oauth2/token"),
		ProfileEndpoint:       getEnvOrDefault("AUTH_TWITTER_PROFILE_ENDPOINT", "https://api.twitter.com/2/users/me"),
		HTTPTimeout:           parseDuration("AUTH_TWITTER_HTTP_TIMEOUT", 10*time.Second),
		RedirectPath:          getEnvOrDefault("AUTH_TWITTER_REDIRECT_PATH", "/"),
		DefaultRedirectOrigin: strings.TrimSpace(os.Getenv("AUTH_TWITTER_DEFAULT_REDIRECT_ORIGIN")),
	}

	if cfg.ClientID == "" {
		return Config{}, fmt.Errorf("AUTH_TWITTER_CLIENT_ID is required")
	}
	if cfg.RedirectURI == "" {
		return Config{}, fmt.Errorf("AUTH_TWITTER_REDIRECT_URI is required")
	}
	if len(cfg.StateSecret) == 0 {
		return Config{}, fmt.Errorf("AUTH_TWITTER_STATE_SECRET is required")
	}
	if len(cfg.JWTSecret) == 0 {
		return Config{}, fmt.Errorf("AUTH_TWITTER_JWT_SECRET is required")
	}
	if cfg.StateTTL <= 0 {
		return Config{}, fmt.Errorf("AUTH_TWITTER_STATE_TTL must be positive")
	}
	if cfg.JWTExpiresIn <= 0 {
		return Config{}, fmt.Errorf("AUTH_TWITTER_JWT_EXPIRES_IN must be positive")
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
