package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	cfg        Config
	logger     *log.Logger
	stateMgr   *stateManager
	httpClient *http.Client
}

type loginRequest struct {
	Origin string `json:"origin"`
}

type loginResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`
	State            string `json:"state"`
}

type loginResultPayload struct {
	AccessToken string        `json:"accessToken"`
	TokenType   string        `json:"tokenType"`
	ExpiresIn   int           `json:"expiresIn"`
	LineUser    loginLineUser `json:"lineUser"`
}

type loginLineUser struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
}

func NewServer(cfg Config, logger *log.Logger) *Server {
	client := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}
	return &Server{
		cfg:        cfg,
		logger:     logger,
		stateMgr:   newStateManager(cfg.StateSecret, cfg.StateTTL),
		httpClient: client,
	}
}

func (s *Server) Routes() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(30 * time.Second))
	router.Use(middleware.RequestLogger(&middleware.DefaultLogFormatter{
		Logger:  s.logger,
		NoColor: true,
	}))

	router.Get("/healthz", s.handleHealthz)
	router.Options("/line/login", s.handlePreflight)
	router.Post("/line/login", s.handleLoginStart)
	router.Get("/line/callback", s.handleCallback)

	return router
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	io.WriteString(w, `{"status":"ok"}`)
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if !s.isOriginAllowed(origin) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.applyCORSHeaders(w, origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	origin := r.Header.Get("Origin")
	if origin != "" && !s.isOriginAllowed(origin) {
		s.logger.Printf("login start rejected: origin %q not allowed", origin)
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Printf("failed to decode login request: %v", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.Origin = strings.TrimSpace(req.Origin)
	if req.Origin == "" {
		if origin == "" {
			http.Error(w, "origin is required", http.StatusBadRequest)
			return
		}
		req.Origin = origin
	}
	if !s.isOriginAllowed(req.Origin) {
		s.logger.Printf("login start rejected: origin %q not allowed", req.Origin)
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	s.applyCORSHeaders(w, req.Origin)

	state, _, err := s.stateMgr.issue(req.Origin)
	if err != nil {
		s.logger.Printf("failed to issue state: %v", err)
		http.Error(w, "failed to start login", http.StatusInternalServerError)
		return
	}

	authURL := s.buildAuthorizeURL(state)

	resp := loginResponse{
		AuthorizationURL: authURL,
		State:            state,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Printf("failed to encode login response: %v", err)
	}
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	errorCode := r.URL.Query().Get("error")
	if errorCode != "" {
		errorDescription := r.URL.Query().Get("error_description")
		s.logger.Printf("LINE login returned error: %s (%s)", errorCode, errorDescription)
		s.renderResultPage(w, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			Error:   fmt.Sprintf("LINE認証がキャンセルされました: %s", errorCode),
		})
		return
	}

	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")
	if code == "" || stateParam == "" {
		http.Error(w, "invalid callback parameters", http.StatusBadRequest)
		return
	}

	payload, err := s.stateMgr.verify(stateParam)
	if err != nil {
		if errors.Is(err, ErrStateExpired) {
			s.renderResultPage(w, loginResult{
				Type:    loginResultMessageType,
				Success: false,
				State:   stateParam,
				Error:   "ログインの有効期限が切れました。もう一度お試しください。",
			})
			return
		}
		s.logger.Printf("state verification failed: %v", err)
		s.renderResultPage(w, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Error:   "無効なログイン試行です。再度お試しください。",
		})
		return
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.HTTPTimeout)
	defer cancel()

	tokenResp, err := s.exchangeToken(ctx, code)
	if err != nil {
		s.logger.Printf("failed to exchange token: %v", err)
		s.renderResultPage(w, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Error:   "LINE認証との通信に失敗しました。時間を置いて再度お試しください。",
		})
		return
	}

	profile, err := s.fetchProfile(ctx, tokenResp.AccessToken)
	if err != nil {
		s.logger.Printf("failed to fetch profile: %v", err)
		s.renderResultPage(w, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Error:   "LINEプロフィールの取得に失敗しました。",
		})
		return
	}

	appToken, expiresIn, err := s.issueAppToken(profile)
	if err != nil {
		s.logger.Printf("failed to issue app token: %v", err)
		s.renderResultPage(w, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Error:   "アクセストークンの生成に失敗しました。",
		})
		return
	}

	result := loginResult{
		Type:    loginResultMessageType,
		Success: true,
		State:   stateParam,
		Origin:  payload.Origin,
		Payload: &loginResultPayload{
			AccessToken: appToken,
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
			LineUser: loginLineUser{
				UserID:      profile.UserID,
				DisplayName: profile.DisplayName,
				AvatarURL:   profile.PictureURL,
			},
		},
	}

	s.renderResultPage(w, result)
}

func (s *Server) issueAppToken(profile *lineProfile) (string, int, error) {
	now := time.Now().UTC()
	expiry := now.Add(s.cfg.JWTExpiresIn)

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	payload := map[string]any{
		"sub": profile.UserID,
		"iss": s.cfg.JWTIssuer,
		"iat": now.Unix(),
		"exp": expiry.Unix(),
	}
	if profile.DisplayName != "" {
		payload["name"] = profile.DisplayName
	}
	if profile.PictureURL != "" {
		payload["picture"] = profile.PictureURL
	}
	if s.cfg.JWTAudience != "" {
		payload["aud"] = s.cfg.JWTAudience
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal token header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal token payload: %w", err)
	}

	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	mac := hmac.New(sha256.New, s.cfg.JWTSecret)
	mac.Write([]byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + signature, int(s.cfg.JWTExpiresIn.Seconds()), nil
}

const loginResultMessageType = "line-login-result"

type loginResult struct {
	Type    string              `json:"type"`
	Success bool                `json:"success"`
	State   string              `json:"state,omitempty"`
	Origin  string              `json:"origin,omitempty"`
	Error   string              `json:"error,omitempty"`
	Payload *loginResultPayload `json:"payload,omitempty"`
}

func (s *Server) renderResultPage(w http.ResponseWriter, result loginResult) {
	origin := result.Origin
	if origin == "" {
		if payload, err := s.stateMgr.verify(result.State); err == nil {
			origin = payload.Origin
		}
	}
	data, err := json.Marshal(result)
	if err != nil {
		s.logger.Printf("failed to marshal login result: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if origin == "" {
		origin = "*"
	}

	page := fmt.Sprintf(`<!DOCTYPE html>
<html lang="ja">
  <head>
    <meta charset="utf-8" />
    <title>LINE ログイン</title>
    <style>
      body { font-family: system-ui, sans-serif; padding: 24px; text-align: center; }
    </style>
  </head>
  <body>
    <p>このウィンドウは自動的に閉じます。</p>
    <script>
      (function() {
        const data = JSON.parse(%q);
        const targetOrigin = %q;
        if (window.opener && !window.opener.closed && targetOrigin !== "*") {
          window.opener.postMessage(data, targetOrigin);
          window.close();
        } else {
          document.body.insertAdjacentHTML('beforeend', '<p>ウィンドウを閉じて元の画面に戻ってください。</p>');
        }
      })();
    </script>
  </body>
</html>`, string(data), origin)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, page)
}

func (s *Server) isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	if len(s.cfg.AllowedOrigins) == 0 {
		return true
	}
	_, ok := s.cfg.AllowedOrigins[origin]
	return ok
}

func (s *Server) applyCORSHeaders(w http.ResponseWriter, origin string) {
	if !s.isOriginAllowed(origin) {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
}
