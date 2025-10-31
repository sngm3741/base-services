package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type exchangeTokenParams struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Code         string
	CodeVerifier string
	TokenURL     string
	HTTPClient   *http.Client
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type fetchProfileParams struct {
	AccessToken string
	ProfileURL  string
	HTTPClient  *http.Client
}

type twitterProfile struct {
	ID        string
	Name      string
	Username  string
	AvatarURL string
}

func exchangeToken(ctx context.Context, params exchangeTokenParams) (*tokenResponse, error) {
	if params.HTTPClient == nil {
		return nil, errors.New("http client is nil")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", params.Code)
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("code_verifier", params.CodeVerifier)
	form.Set("client_id", params.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, params.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if params.ClientSecret != "" {
		credential := base64.StdEncoding.EncodeToString([]byte(params.ClientID + ":" + params.ClientSecret))
		req.Header.Set("Authorization", "Basic "+credential)
	}

	res, err := params.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("twitter token endpoint returned %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	if token.AccessToken == "" {
		return nil, errors.New("twitter token response missing access_token")
	}

	return &token, nil
}

func fetchProfile(ctx context.Context, params fetchProfileParams) (*twitterProfile, error) {
	if params.HTTPClient == nil {
		return nil, errors.New("http client is nil")
	}

	profileURL, err := url.Parse(params.ProfileURL)
	if err != nil {
		return nil, fmt.Errorf("invalid profile url: %w", err)
	}
	query := profileURL.Query()
	if query.Get("user.fields") == "" {
		query.Set("user.fields", "name,username,profile_image_url")
	}
	profileURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+params.AccessToken)

	res, err := params.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send profile request: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read profile response: %w", err)
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("twitter profile endpoint returned %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Data struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to decode profile response: %w", err)
	}

	if payload.Data.ID == "" {
		return nil, errors.New("twitter profile response missing id")
	}

	return &twitterProfile{
		ID:        payload.Data.ID,
		Name:      payload.Data.Name,
		Username:  payload.Data.Username,
		AvatarURL: payload.Data.ProfileImageURL,
	}, nil
}
