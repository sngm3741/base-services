package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const defaultReadTimeout = 10 * time.Second

func NewRouter(s *Server) http.Handler {
	r := chi.NewRouter()
	r.Use(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Recoverer,
		middleware.Timeout(defaultReadTimeout),
		corsMiddleware,
	)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Post("/uploads", s.handleUpload)

	return r
}

type Server struct {
	cfg     Config
	storage *Storage
	logger  Logger
}

type Logger interface {
	Printf(format string, v ...interface{})
}

func NewServer(cfg Config, storage *Storage, logger Logger) *Server {
	return &Server{cfg: cfg, storage: storage, logger: logger}
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+1024)
	if err := r.ParseMultipartForm(s.cfg.MaxUploadBytes); err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "file field is required")
		return
	}
	defer file.Close()

	buf := &bytes.Buffer{}
	n, err := io.Copy(buf, file)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "failed to read file")
		return
	}

	if n > s.cfg.MaxUploadBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "file is too large")
		return
	}

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = http.DetectContentType(buf.Bytes())
	}

	if !s.isAllowedContentType(contentType) {
		s.writeError(w, http.StatusBadRequest, "unsupported content type")
		return
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext == "" {
		exts, _ := mime.ExtensionsByType(contentType)
		if len(exts) > 0 {
			ext = exts[0]
		}
	}
	if ext == "" {
		ext = ".bin"
	}

	key := uuid.New().String() + ext
	url, err := s.storage.Upload(r.Context(), key, contentType, bytes.NewReader(buf.Bytes()), n)
	if err != nil {
		s.log("upload failed: %v", err)
		s.writeError(w, http.StatusInternalServerError, "upload failed")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"url": url,
		"key": key,
	})
}

func (s *Server) isAllowedContentType(ct string) bool {
	if len(s.cfg.AllowedTypes) == 0 {
		return true
	}
	for _, allowed := range s.cfg.AllowedTypes {
		if strings.HasSuffix(allowed, "/*") {
			prefix := strings.TrimSuffix(allowed, "/*")
			if strings.HasPrefix(ct, prefix) {
				return true
			}
		} else if strings.HasPrefix(ct, allowed) {
			return true
		}
	}
	return false
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) log(format string, v ...interface{}) {
	if s.logger != nil {
		s.logger.Printf(format, v...)
	}
}

// handleErrorは未使用だが、拡張時に備えたプレースホルダー
func handleError(err error) int {
	if errors.Is(err, ErrMissingEnv{}) {
		return http.StatusInternalServerError
	}
	return http.StatusInternalServerError
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
