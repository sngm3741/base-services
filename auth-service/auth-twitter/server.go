package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	cfg           Config
	logger        *log.Logger
	stateMgr      *stateManager
	httpClient    *http.Client
	verifierStore *verifierStore
}

type loginRequest struct {
	Origin string `json:"origin"`
}

type loginResponse struct {
	AuthorizationURL string `json:"authorizationUrl"`
	State            string `json:"state"`
}

type loginResultPayload struct {
	AccessToken string           `json:"accessToken"`
	TokenType   string           `json:"tokenType"`
	ExpiresIn   int              `json:"expiresIn"`
	TwitterUser loginTwitterUser `json:"twitterUser"`
}

type loginTwitterUser struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
}

type loginResult struct {
	Type    string              `json:"type"`
	Success bool                `json:"success"`
	State   string              `json:"state,omitempty"`
	Origin  string              `json:"origin,omitempty"`
	Error   string              `json:"error,omitempty"`
	Payload *loginResultPayload `json:"payload,omitempty"`
}

const (
	loginResultMessageType = "oauth-login-result"
	hashPrefix             = "#oauth-login="
)

func NewServer(cfg Config, logger *log.Logger) *Server {
	client := &http.Client{Timeout: cfg.HTTPTimeout}
	return &Server{
		cfg:           cfg,
		logger:        logger,
		stateMgr:      newStateManager(cfg.StateSecret, cfg.StateTTL),
		httpClient:    client,
		verifierStore: newVerifierStore(),
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
	router.Options("/twitter/login", s.handlePreflight)
	router.Post("/twitter/login", s.handleLoginStart)
	router.Get("/twitter/callback", s.handleCallback)

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

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		s.logger.Printf("failed to generate code verifier: %v", err)
		http.Error(w, "failed to start login", http.StatusInternalServerError)
		return
	}

	codeChallenge := codeChallengeS256(codeVerifier)
	s.verifierStore.Store(state, codeVerifier)

	authURL := s.buildAuthorizeURL(state, codeChallenge)

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
	stateParam := r.URL.Query().Get("state")

	if errorCode := r.URL.Query().Get("error"); errorCode != "" {
		errorDescription := r.URL.Query().Get("error_description")
		s.logger.Printf("Twitter login returned error: %s (%s)", errorCode, errorDescription)
		result := loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Error:   fmt.Sprintf("X認証がキャンセルされました: %s", errorCode),
		}
		if payload, err := s.stateMgr.decode(stateParam); err == nil {
			result.Origin = payload.Origin
		}
		s.redirectWithResult(w, r, result)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" || stateParam == "" {
		result := loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Error:   "無効なログイン応答です。再度お試しください。",
		}
		if payload, err := s.stateMgr.decode(stateParam); err == nil {
			result.Origin = payload.Origin
		}
		s.redirectWithResult(w, r, result)
		return
	}

	payload, err := s.stateMgr.verify(stateParam)
	if err != nil {
		result := loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
		}
		if errors.Is(err, ErrStateExpired) {
			result.Error = "ログインの有効期限が切れました。もう一度お試しください。"
		} else {
			s.logger.Printf("state verification failed: %v", err)
			result.Error = "無効なログイン試行です。再度お試しください。"
		}
		if extracted, decodeErr := s.stateMgr.decode(stateParam); decodeErr == nil {
			result.Origin = extracted.Origin
		}
		s.redirectWithResult(w, r, result)
		return
	}

	codeVerifier, ok := s.verifierStore.Take(stateParam)
	if !ok {
		s.logger.Printf("code verifier missing for state %s", stateParam)
		result := loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Origin:  payload.Origin,
			Error:   "ログインの有効期限が切れました。もう一度お試しください。",
		}
		s.redirectWithResult(w, r, result)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.HTTPTimeout)
	defer cancel()

	tokenResp, err := s.exchangeToken(ctx, code, codeVerifier)
	if err != nil {
		s.logger.Printf("failed to exchange token: %v", err)
		s.redirectWithResult(w, r, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Origin:  payload.Origin,
			Error:   "X認証との通信に失敗しました。時間を置いて再度お試しください。",
		})
		return
	}

	profile, err := s.fetchProfile(ctx, tokenResp.AccessToken)
	if err != nil {
		s.logger.Printf("failed to fetch profile: %v", err)
		s.redirectWithResult(w, r, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Origin:  payload.Origin,
			Error:   "Xプロフィールの取得に失敗しました。",
		})
		return
	}

	appToken, expiresIn, err := s.issueAppToken(profile)
	if err != nil {
		s.logger.Printf("failed to issue app token: %v", err)
		s.redirectWithResult(w, r, loginResult{
			Type:    loginResultMessageType,
			Success: false,
			State:   stateParam,
			Origin:  payload.Origin,
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
			TwitterUser: loginTwitterUser{
				UserID:      profile.ID,
				Username:    profile.Username,
				DisplayName: profile.Name,
				AvatarURL:   profile.AvatarURL,
			},
		},
	}

	s.redirectWithResult(w, r, result)
}

func (s *Server) buildAuthorizeURL(state, codeChallenge string) string {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", s.cfg.ClientID)
	values.Set("redirect_uri", s.cfg.RedirectURI)
	values.Set("scope", strings.Join(s.cfg.Scopes, " "))
	values.Set("state", state)
	values.Set("code_challenge", codeChallenge)
	values.Set("code_challenge_method", "S256")

	return fmt.Sprintf("%s?%s", strings.TrimRight(s.cfg.AuthorizeEndpoint, "/"), values.Encode())
}

func (s *Server) exchangeToken(ctx context.Context, code, codeVerifier string) (*tokenResponse, error) {
	return exchangeToken(ctx, exchangeTokenParams{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		RedirectURI:  s.cfg.RedirectURI,
		Code:         code,
		CodeVerifier: codeVerifier,
		TokenURL:     s.cfg.TokenEndpoint,
		HTTPClient:   s.httpClient,
	})
}

func (s *Server) fetchProfile(ctx context.Context, accessToken string) (*twitterProfile, error) {
	return fetchProfile(ctx, fetchProfileParams{
		AccessToken: accessToken,
		ProfileURL:  s.cfg.ProfileEndpoint,
		HTTPClient:  s.httpClient,
	})
}

func (s *Server) issueAppToken(profile *twitterProfile) (string, int, error) {
	now := time.Now().UTC()
	expiry := now.Add(s.cfg.JWTExpiresIn)

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}

	payload := map[string]any{
		"sub": profile.ID,
		"iss": s.cfg.JWTIssuer,
		"iat": now.Unix(),
		"exp": expiry.Unix(),
	}

	if profile.Name != "" {
		payload["name"] = profile.Name
	}
	if profile.AvatarURL != "" {
		payload["picture"] = profile.AvatarURL
	}
	if profile.Username != "" {
		payload["preferred_username"] = profile.Username
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
	mac := hmacSHA256(s.cfg.JWTSecret, []byte(unsigned))
	signature := base64.RawURLEncoding.EncodeToString(mac)

	return unsigned + "." + signature, int(s.cfg.JWTExpiresIn.Seconds()), nil
}

func (s *Server) redirectWithResult(w http.ResponseWriter, r *http.Request, result loginResult) {
	target, err := s.buildRedirectURL(result)
	if err != nil {
		s.logger.Printf("failed to build redirect URL: %v", err)
		s.renderFallbackPage(w, result)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) buildRedirectURL(result loginResult) (string, error) {
	origin := strings.TrimSpace(result.Origin)
	if origin == "" && result.State != "" {
		if payload, err := s.stateMgr.decode(result.State); err == nil {
			origin = payload.Origin
		}
	}
	if origin == "" {
		origin = strings.TrimSpace(s.cfg.DefaultRedirectOrigin)
	}
	if origin == "" {
		return "", fmt.Errorf("redirect origin is empty")
	}

	base, err := url.Parse(origin)
	if err != nil {
		return "", fmt.Errorf("invalid redirect origin %q: %w", origin, err)
	}

	path := strings.TrimSpace(s.cfg.RedirectPath)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	base.Path = path
	base.RawQuery = ""

	data, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal login result: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(data)
	base.Fragment = hashPrefix + encoded

	return base.String(), nil
}

func (s *Server) renderFallbackPage(w http.ResponseWriter, result loginResult) {
	message := "Xログインが完了しました。元の画面に戻ってください。"
	if !result.Success && result.Error != "" {
		message = result.Error
	}

	var linkHTML string
	redirectOrigin := strings.TrimSpace(s.cfg.DefaultRedirectOrigin)
	if redirectOrigin != "" {
		path := strings.TrimSpace(s.cfg.RedirectPath)
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		link := strings.TrimRight(redirectOrigin, "/") + path
		linkHTML = fmt.Sprintf(
			`<p><a href="%s">こちらをタップして戻ってください。</a></p>`,
			template.HTMLEscapeString(link),
		)
	}

	html := fmt.Sprintf(
		`<!DOCTYPE html>
<html lang="ja">
  <head>
    <meta charset="utf-8" />
    <title>X認証</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style>
      body { font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; background: #f8fafc; }
      .card { padding: 24px; border-radius: 16px; background: white; box-shadow: 0 12px 30px rgba(15, 23, 42, 0.12); max-width: 360px; text-align: center; }
      h1 { font-size: 20px; margin-bottom: 12px; color: #0f172a; }
      p { font-size: 14px; color: #334155; }
      a { color: #1d9bf0; text-decoration: none; }
      a:hover { text-decoration: underline; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>X認証</h1>
      <p>%s</p>
      %s
    </div>
  </body>
</html>`,
		template.HTMLEscapeString(message),
		linkHTML,
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
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
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
}

func hmacSHA256(secret, message []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}

type verifierStore struct {
	mu   sync.Mutex
	data map[string]string
}

func newVerifierStore() *verifierStore {
	return &verifierStore{data: make(map[string]string)}
}

func (s *verifierStore) Store(state, verifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[state] = verifier
}

func (s *verifierStore) Take(state string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	verifier, ok := s.data[state]
	if ok {
		delete(s.data, state)
	}
	return verifier, ok
}

func generateCodeVerifier() (string, error) {
	return randomString(64)
}

func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
