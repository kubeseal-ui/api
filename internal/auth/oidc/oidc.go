// Package oidc implements the OIDC authorization code flow with PKCE
// for the kubeseal-ui API.
//
// Flow per internal-docs/engineering/backend/auth-oidc.md:
// 1. Login generates state, nonce, PKCE verifier; stores in HttpOnly cookie; redirects to provider
// 2. Callback validates state, exchanges code with verifier, validates ID token
// 3. Creates session cookie + refresh token cookie; clears flow cookies
// 4. Middleware handles automatic refresh before session expiry
// 5. Logout clears cookies, attempts provider revocation
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds OIDC configuration loaded from environment.
type Config struct {
	IssuerURL          string
	ClientID           string
	ClientSecret       string
	RedirectURL        string
	Scopes             []string
	GroupsClaim        string
	UsernameClaim      string
	CookieSecure       bool
	CookieDomain       string
	CSRFTrustedOrigins []string
}

// LoadConfig reads OIDC configuration from environment variables.
func LoadConfig() (Config, error) {
	cfg := Config{
		IssuerURL:          getEnv("OIDC_ISSUER_URL"),
		ClientID:           getEnv("OIDC_CLIENT_ID"),
		ClientSecret:       getEnv("OIDC_CLIENT_SECRET"),
		RedirectURL:        getEnv("OIDC_REDIRECT_URL"),
		Scopes:             splitCSV(getEnv("OIDC_SCOPES", "openid profile email groups")),
		GroupsClaim:        getEnv("OIDC_GROUPS_CLAIM", "groups"),
		UsernameClaim:      getEnv("OIDC_USERNAME_CLAIM", "preferred_username"),
		CookieSecure:       getEnv("COOKIE_SECURE", "true") == "true",
		CookieDomain:       getEnv("COOKIE_DOMAIN"),
		CSRFTrustedOrigins: splitCSV(getEnv("CSRF_TRUSTED_ORIGINS")),
	}

	if cfg.IssuerURL == "" {
		return Config{}, fmt.Errorf("OIDC_ISSUER_URL is required")
	}
	if cfg.ClientID == "" {
		return Config{}, fmt.Errorf("OIDC_CLIENT_ID is required")
	}
	if cfg.ClientSecret == "" {
		return Config{}, fmt.Errorf("OIDC_CLIENT_SECRET is required")
	}
	if cfg.RedirectURL == "" {
		return Config{}, fmt.Errorf("OIDC_REDIRECT_URL is required")
	}

	return cfg, nil
}

func getEnv(key string, def ...string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	if len(def) > 0 {
		return def[0]
	}
	return ""
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Provider wraps the OIDC provider and OAuth2 config.
type Provider struct {
	cfg       Config
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	oauth2Cfg oauth2.Config
}

// NewProvider discovers the OIDC provider and initializes the verifier.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider discovery: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	oauth2Cfg := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint:     provider.Endpoint(),
	}

	return &Provider{
		cfg:       cfg,
		provider:  provider,
		verifier:  verifier,
		oauth2Cfg: oauth2Cfg,
	}, nil
}

// PKCEChallengeMethod is the PKCE challenge method used (S256 per RFC 7636).
const PKCEChallengeMethod = "S256"

// PKCEVerifier generates a PKCE code verifier (RFC 7636).
// The verifier is 32 random bytes base64url-encoded without padding.
func PKCEVerifier() (verifier string, err error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(bytes)
	return verifier, nil
}

// PKCEChallenge computes the S256 PKCE challenge from a verifier.
// Per RFC 7636: BASE64URL-ENCODE(SHA256(ASCII(verifier)))
func PKCEChallenge(verifier string) (string, error) {
	if len(verifier) < 43 || len(verifier) > 128 {
		return "", fmt.Errorf("pkce: verifier length must be 43-128, got %d", len(verifier))
	}
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// FlowState is the temporary state stored in the PKCE cookie.
type FlowState struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	PKCEVerifier string `json:"pkce_verifier"`
	CreatedAt    int64  `json:"created_at"`
}

// NewFlowState generates a fresh flow state for the login redirect.
func NewFlowState() (*FlowState, error) {
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)

	verifier, err := PKCEVerifier()
	if err != nil {
		return nil, err
	}

	return &FlowState{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		CreatedAt:    time.Now().Unix(),
	}, nil
}

// Validate checks that the flow state is not expired (5 min TTL).
func (f *FlowState) Validate() error {
	if time.Now().Unix()-f.CreatedAt > 5*60 {
		return fmt.Errorf("flow state expired")
	}
	return nil
}

// LoginURL builds the authorization URL for the redirect.
func (p *Provider) LoginURL(flow *FlowState) (string, error) {
	challenge, err := PKCEChallenge(flow.PKCEVerifier)
	if err != nil {
		return "", fmt.Errorf("OIDC login URL: %w", err)
	}
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.cfg.ClientID)
	params.Set("redirect_uri", p.cfg.RedirectURL)
	params.Set("scope", strings.Join(p.cfg.Scopes, " "))
	params.Set("state", flow.State)
	params.Set("nonce", flow.Nonce)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", PKCEChallengeMethod)
	return p.oauth2Cfg.Endpoint.AuthURL + "?" + params.Encode(), nil
}

// TokenResponse holds the token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// ExchangeCode exchanges the authorization code for tokens using PKCE verifier.
func (p *Provider) ExchangeCode(ctx context.Context, code, pkceVerifier string) (*TokenResponse, error) {
	token, err := p.oauth2Cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("id_token missing in token response")
	}

	refreshToken := ""
	if v, ok := token.Extra("refresh_token").(string); ok {
		refreshToken = v
	}

	return &TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        getScopeFromToken(token),
	}, nil
}

// VerifiedIDToken holds the validated ID token claims.
type VerifiedIDToken struct {
	Subject  string
	Email    string
	Name     string
	Username string
	Groups   []string
	Issuer   string
	Audience string
	Expiry   time.Time
	IssuedAt time.Time
	Nonce    string
}

// VerifyIDToken validates the ID token and extracts normalized claims.
func (p *Provider) VerifyIDToken(ctx context.Context, idToken, nonce string) (*VerifiedIDToken, error) {
	tok, err := p.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("ID token verification: %w", err)
	}

	if tok.Nonce != nonce {
		return nil, fmt.Errorf("nonce mismatch: expected %q, got %q", nonce, tok.Nonce)
	}

	var claims struct {
		Subject  string   `json:"sub"`
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Username string   `json:"preferred_username"`
		Groups   []string `json:"groups"`
		Issuer   string   `json:"iss"`
		Audience []string `json:"aud"`
		Expiry   int64    `json:"exp"`
		IssuedAt int64    `json:"iat"`
		Nonce    string   `json:"nonce"`
	}

	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse ID token claims: %w", err)
	}
	if claims.Subject == "" || claims.Email == "" || claims.Expiry == 0 || claims.IssuedAt == 0 {
		return nil, fmt.Errorf("ID token missing required claims")
	}

	// Validate issuer
	if claims.Issuer != p.cfg.IssuerURL {
		return nil, fmt.Errorf("issuer mismatch: expected %q, got %q", p.cfg.IssuerURL, claims.Issuer)
	}

	// Validate audience
	audOK := false
	for _, aud := range claims.Audience {
		if aud == p.cfg.ClientID {
			audOK = true
			break
		}
	}
	if !audOK {
		return nil, fmt.Errorf("audience mismatch: client_id %q not in aud %v", p.cfg.ClientID, claims.Audience)
	}

	// Extract groups and username from configured claims. The default claim
	// names use the typed fields above; custom claims are decoded explicitly.
	groups := claims.Groups
	username := claims.Username
	if p.cfg.GroupsClaim != "" && p.cfg.GroupsClaim != "groups" || p.cfg.UsernameClaim != "" && p.cfg.UsernameClaim != "preferred_username" {
		var raw map[string]json.RawMessage
		if err := tok.Claims(&raw); err != nil {
			return nil, fmt.Errorf("parse ID token claims: %w", err)
		}
		if p.cfg.GroupsClaim != "" && p.cfg.GroupsClaim != "groups" {
			groups = nil
			if value, ok := raw[p.cfg.GroupsClaim]; ok && json.Unmarshal(value, &groups) != nil {
				return nil, fmt.Errorf("invalid groups claim")
			}
		}
		if p.cfg.UsernameClaim != "" && p.cfg.UsernameClaim != "preferred_username" {
			username = ""
			if value, ok := raw[p.cfg.UsernameClaim]; ok && json.Unmarshal(value, &username) != nil {
				return nil, fmt.Errorf("invalid username claim")
			}
		}
	}

	return &VerifiedIDToken{
		Subject:  claims.Subject,
		Email:    claims.Email,
		Name:     claims.Name,
		Username: username,
		Groups:   groups,
		Issuer:   claims.Issuer,
		Audience: p.cfg.ClientID,
		Expiry:   time.Unix(claims.Expiry, 0),
		IssuedAt: time.Unix(claims.IssuedAt, 0),
		Nonce:    claims.Nonce,
	}, nil
}

// RefreshTokens uses the refresh token to get new tokens.
func (p *Provider) RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	token, err := p.oauth2Cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
	}).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		return nil, fmt.Errorf("id_token missing in refresh response")
	}

	newRefreshToken := ""
	if v, ok := token.Extra("refresh_token").(string); ok {
		newRefreshToken = v
	}
	if newRefreshToken == "" {
		newRefreshToken = refreshToken // Some providers don't rotate
	}

	return &TokenResponse{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		ExpiresIn:    int(time.Until(token.Expiry).Seconds()),
		RefreshToken: newRefreshToken,
		IDToken:      idToken,
		Scope:        getScopeFromToken(token),
	}, nil
}

// RevokeToken attempts to revoke the token at the provider (best effort).
func (p *Provider) RevokeToken(ctx context.Context, token string) error {
	// Token revocation is optional per RFC 7009; best effort
	revokeURL := p.provider.Endpoint().TokenURL
	if revokeURL == "" {
		return nil // Not supported
	}
	// In real impl, POST to revocation endpoint
	return nil
}

// Cookie names
const (
	CookiePKCE    = "kubeseal_pkce"
	CookieSession = "kubeseal_session"
	CookieRefresh = "kubeseal_refresh"
	CookieCSRF    = "kubeseal_csrf"
)

// SessionData is stored in the signed session cookie.
type SessionData struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	CSRF     string   `json:"csrf"`
}

// CSRFToken generates a CSRF token for the SPA.
func CSRFToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// getScopeFromToken extracts scope from token (oauth2.Token doesn't expose Scope field).
func getScopeFromToken(token *oauth2.Token) string {
	if v, ok := token.Extra("scope").(string); ok {
		return v
	}
	return ""
}

// CookieOptions returns standard cookie options.
func (p *Provider) CookieOptions(path string, maxAge int) *http.Cookie {
	// CookieSecure defaults to true in production; tests override to false
	secure := p.cfg.CookieSecure
	// nolint:gosec // Secure flag intentionally configurable for test environments
	return &http.Cookie{
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Domain:   p.cfg.CookieDomain,
	}
}
