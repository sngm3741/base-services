package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type lineTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type lineProfile struct {
	UserID        string `json:"userId"`
	DisplayName   string `json:"displayName"`
	PictureURL    string `json:"pictureUrl"`
	StatusMessage string `json:"statusMessage"`
}

func (s *Server) exchangeToken(ctx context.Context, code string) (*lineTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.RedirectURI)
	form.Set("client_id", s.cfg.ChannelID)
	form.Set("client_secret", s.cfg.ChannelSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed lineTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, errors.New("token response missing access_token")
	}
	return &parsed, nil
}

func (s *Server) fetchProfile(ctx context.Context, accessToken string) (*lineProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.ProfileEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("profile request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("profile endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var profile lineProfile
	if err := json.NewDecoder(resp.Body).Decode(&profile); err != nil {
		return nil, fmt.Errorf("failed to decode profile response: %w", err)
	}
	if profile.UserID == "" {
		return nil, errors.New("profile response missing userId")
	}
	return &profile, nil
}

func (s *Server) buildAuthorizeURL(state string) string {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", s.cfg.ChannelID)
	values.Set("redirect_uri", s.cfg.RedirectURI)
	values.Set("state", state)
	values.Set("scope", strings.Join(s.cfg.Scopes, " "))
	if s.cfg.BotPrompt != "" {
		values.Set("bot_prompt", s.cfg.BotPrompt)
	}
	return fmt.Sprintf("%s?%s", s.cfg.AuthorizeEndpoint, values.Encode())
}
