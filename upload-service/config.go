package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	HTTPAddr        string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	Bucket          string
	PublicBaseURL   string
	MaxUploadBytes  int64
	AllowedTypes    []string
}

const (
	defaultHTTPAddr       = ":8080"
	defaultMaxUploadBytes = int64(10 * 1024 * 1024) // 10MB
)

func LoadConfig() Config {
	cfg := Config{
		HTTPAddr:        getEnv("UPLOAD_HTTP_ADDR", defaultHTTPAddr),
		Endpoint:        os.Getenv("R2_ENDPOINT"),
		AccessKeyID:     os.Getenv("R2_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("R2_SECRET_ACCESS_KEY"),
		Bucket:          os.Getenv("R2_BUCKET"),
		PublicBaseURL:   strings.TrimSuffix(os.Getenv("UPLOAD_PUBLIC_BASE"), "/"),
		MaxUploadBytes:  defaultMaxUploadBytes,
		AllowedTypes:    []string{"image/"},
	}

	if v := os.Getenv("UPLOAD_MAX_UPLOAD_BYTES"); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil && parsed > 0 {
			cfg.MaxUploadBytes = parsed
		}
	}

	if v := os.Getenv("UPLOAD_ALLOWED_TYPES"); v != "" {
		parts := strings.Split(v, ",")
		allowed := make([]string, 0, len(parts))
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				allowed = append(allowed, trimmed)
			}
		}
		if len(allowed) > 0 {
			cfg.AllowedTypes = allowed
		}
	}

	return cfg
}

func (c Config) Validate() error {
	missing := []string{}
	if c.Endpoint == "" {
		missing = append(missing, "R2_ENDPOINT")
	}
	if c.AccessKeyID == "" {
		missing = append(missing, "R2_ACCESS_KEY_ID")
	}
	if c.SecretAccessKey == "" {
		missing = append(missing, "R2_SECRET_ACCESS_KEY")
	}
	if c.Bucket == "" {
		missing = append(missing, "R2_BUCKET")
	}
	if len(missing) > 0 {
		return ErrMissingEnv{Keys: missing}
	}
	return nil
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// ErrMissingEnv は不足している環境変数のリストを持つエラー。
type ErrMissingEnv struct {
	Keys []string
}

func (e ErrMissingEnv) Error() string {
	return "missing required environment variables: " + strings.Join(e.Keys, ", ")
}

func fatalIfErr(logger *log.Logger, msg string, err error) {
	if err == nil {
		return
	}
	logger.Fatalf("%s: %v", msg, err)
}
