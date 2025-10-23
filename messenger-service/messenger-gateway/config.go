package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config aggregates all runtime settings required by the gateway.
type Config struct {
	HTTPAddr           string
	NATSURL            string
	Subjects           map[string]string
	DefaultDestination string
	RequestTimeout     time.Duration
}

const (
	defaultHTTPAddr       = ":3000"
	defaultNATSURL        = "nats://nats:4222"
	defaultLineSubject    = "line.events"
	defaultRequestTimeout = 5 * time.Second
)

var (
	destinationsKeys = []string{
		"MESSENGER_GATEWAY_DESTINATIONS",
		"CORE_DESTINATIONS",
	}
	defaultDestinationKeys = []string{
		"MESSENGER_GATEWAY_DEFAULT_DESTINATION",
		"CORE_DEFAULT_DESTINATION",
		"MESSENGER_DEFAULT_DESTINATION",
	}
	requestTimeoutKeys = []string{
		"MESSENGER_GATEWAY_REQUEST_TIMEOUT",
		"CORE_REQUEST_TIMEOUT",
	}
)

// LoadConfig constructs Config by reading environment variables and applying sensible defaults.
func LoadConfig() Config {
	subjects := loadSubjects()
	return Config{
		HTTPAddr:           firstEnv([]string{"MESSENGER_GATEWAY_HTTP_ADDR", "CORE_HTTP_ADDR"}, defaultHTTPAddr),
		NATSURL:            firstEnv([]string{"NATS_URL"}, defaultNATSURL),
		Subjects:           subjects,
		DefaultDestination: resolveDefaultDestination(subjects),
		RequestTimeout:     parseDurationEnv(requestTimeoutKeys, defaultRequestTimeout),
	}
}

func loadSubjects() map[string]string {
	subjects := make(map[string]string)

	if raw := firstEnv(destinationsKeys, ""); raw != "" {
		for _, pair := range strings.Split(raw, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key == "" || value == "" {
				continue
			}
			subjects[key] = value
		}
	}

	if lineSubject := firstEnv([]string{"MESSENGER_LINE_EVENTS_SUBJECT", "LINE_EVENTS_SUBJECT"}, ""); lineSubject != "" {
		subjects["line"] = lineSubject
	}

	if len(subjects) == 0 {
		subjects["line"] = defaultLineSubject
	} else if _, ok := subjects["line"]; !ok {
		subjects["line"] = defaultLineSubject
	}

	return subjects
}

func resolveDefaultDestination(subjects map[string]string) string {
	for _, key := range defaultDestinationKeys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			if _, ok := subjects[value]; ok {
				return value
			}
		}
	}

	if _, ok := subjects["line"]; ok {
		return "line"
	}
	for key := range subjects {
		return key
	}
	return ""
}

func firstEnv(keys []string, fallback string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return fallback
}

func parseDurationEnv(keys []string, fallback time.Duration) time.Duration {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		duration, err := time.ParseDuration(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: invalid duration for %s: %v (using fallback %v)\n", key, err, fallback)
			return fallback
		}
		return duration
	}
	return fallback
}
