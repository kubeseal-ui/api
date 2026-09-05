// Package handlers provides the authentication HTTP handlers for the kubeseal-ui API.
//
// Handlers:
// - GET /api/v1/auth/login       - Initiates OIDC login flow
// - GET /api/v1/auth/callback    - Handles OIDC callback
// - GET /api/v1/auth/me          - Returns current user identity
// - POST /api/v1/auth/logout     - Logs out user
// - GET /api/v1/auth/csrf        - Returns CSRF token for SPA
package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/auth/oidc"
)

// writeJSON writes JSON response and logs any encoding error.
func writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("auth: failed to encode JSON response", "error", err)
	}
}

// AuthHandlers holds dependencies for auth handlers.
type AuthHandlers struct {
	Provider oidc.AuthProvider
	Config   middleware.AuthConfig
	// SigningKey is the HMAC key used to sign session cookies.
	// In production this should come from a secure secret (e.g., Infisical).
	SigningKey []byte
}

// NewAuthHandlers creates new auth handlers.
func NewAuthHandlers(provider oidc.AuthProvider, cfg middleware.AuthConfig, signingKey []byte) *AuthHandlers {
	return &AuthHandlers{
		Provider:   provider,
		Config:     cfg,
		SigningKey: signingKey,
	}
}

// signSession marshals the session data and signs it with HMAC-SHA256.
// The returned string is base64(JSON({SessionData, Signature})).
func (h *AuthHandlers) signSession(session oidc.SessionData) (string, error) {
	sig, err := signData(session, h.SigningKey)
	if err != nil {
		return "", err
	}
	combined := sessionCookieData{
		SessionData: session,
		Signature:   sig,
	}
	raw, err := json.Marshal(combined)
	if err != nil {
		return "", fmt.Errorf("marshal session cookie: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// sessionCookieData mirrors middleware.sessionCookieData so we can
// construct signed session cookies from the handlers package without
// importing the middleware's private type.
type sessionCookieData struct {
	oidc.SessionData
	Signature string `json:"sig"`
}

// signData computes an HMAC-SHA256 signature over the JSON-serialized data.
func signData(data any, key []byte) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal for signing: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// signedFlowState is the encoded PKCE cookie value. The signature covers
// the canonical JSON encoding of the FlowState fields only; `sig` is
// captured in the same envelope for atomic cookie transport but is
// excluded from the bytes that get re-signed on verify.
type signedFlowState struct {
	oidc.FlowState
	Signature string `json:"sig,omitempty"`
}

// flowStateBytes returns the canonical JSON encoding of the embedded
// FlowState fields. The verifier re-derives the signature from these
// bytes alone so an attacker cannot mutate fields without invalidating
// the signature.
func (s signedFlowState) flowStateBytes() ([]byte, error) {
	return json.Marshal(s.FlowState)
}

// signFlowState returns a signed, base64-encoded PKCE cookie payload.
func signFlowState(flow oidc.FlowState, key []byte) (string, error) {
	rawFlow, err := json.Marshal(flow)
	if err != nil {
		return "", fmt.Errorf("marshal flow state: %w", err)
	}
	sig := signDataFromRawBytes(rawFlow, key)
	envelope := signedFlowState{FlowState: flow, Signature: sig}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshal signed envelope: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// verifyFlowState parses the PKCE cookie, verifies its signature, and returns
// the decoded flow. The value never contains characters invalid for cookie
// transport because it is base64url-encoded.
func verifyFlowState(envelopeJSON []byte, sig string, key []byte) (oidc.FlowState, bool) {
	var env signedFlowState
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return oidc.FlowState{}, false
	}
	canonical, err := env.flowStateBytes()
	if err != nil {
		return oidc.FlowState{}, false
	}
	expected := signDataFromRawBytes(canonical, key)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return oidc.FlowState{}, false
	}
	return env.FlowState, true
}

// signDataFromRawBytes computes an HMAC over raw bytes.
func signDataFromRawBytes(raw, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// LoginHandler initiates the OIDC login flow.
// GET /api/v1/auth/login
func (h *AuthHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate flow state
	flow, err := oidc.NewFlowState()
	if err != nil {
		slog.Error("auth: failed to generate flow state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Sign the PKCE cookie value. Without signing, raw JSON cannot survive
	// net/http's cookie transport (the parser drops invalid bytes like '"').
	signed, err := signFlowState(*flow, h.SigningKey)
	if err != nil {
		slog.Error("auth: failed to sign flow state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
	pkceCookie := h.Provider.CookieOptions("/api/v1/auth/callback", 5*60) // 5 min
	pkceCookie.Name = oidc.CookiePKCE
	pkceCookie.Value = signed
	http.SetCookie(w, pkceCookie)

	// Build login URL and redirect
	loginURL, err := h.Provider.LoginURL(flow)
	if err != nil {
		slog.Error("auth: failed to build login URL", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// CallbackHandler handles the OIDC callback.
// GET /api/v1/auth/callback
func (h *AuthHandlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Parse flow state from PKCE cookie
	pkceCookie, err := r.Cookie(oidc.CookiePKCE)
	if err != nil {
		slog.Debug("auth: missing PKCE cookie", "error", err)
		http.Error(w, "invalid flow state", http.StatusBadRequest)
		return
	}

	// Decode the signed cookie value.
	raw, decodeErr := base64.RawURLEncoding.DecodeString(pkceCookie.Value)
	if decodeErr != nil {
		slog.Debug("auth: invalid PKCE cookie encoding", "error", decodeErr)
		http.Error(w, "invalid flow state", http.StatusBadRequest)
		return
	}

	var envelope signedFlowState
	if unmarshalErr := json.Unmarshal(raw, &envelope); unmarshalErr != nil {
		slog.Debug("auth: invalid PKCE cookie format", "error", unmarshalErr)
		http.Error(w, "invalid flow state", http.StatusBadRequest)
		return
	}

	flow, ok := verifyFlowState(raw, envelope.Signature, h.SigningKey)
	if !ok {
		slog.Debug("auth: PKCE cookie signature mismatch")
		http.Error(w, "invalid flow state", http.StatusBadRequest)
		return
	}

	// Validate flow state
	if validateErr := flow.Validate(); validateErr != nil {
		slog.Debug("auth: flow state validation failed", "error", validateErr)
		http.Error(w, "flow state expired", http.StatusBadRequest)
		return
	}

	// Validate state parameter
	state := r.URL.Query().Get("state")
	if state != flow.State {
		slog.Debug("auth: state mismatch", "expected", flow.State, "got", state)
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		slog.Debug("auth: missing authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	ctx := r.Context()
	tokens, err := h.Provider.ExchangeCode(ctx, code, flow.PKCEVerifier)
	if err != nil {
		slog.Error("auth: token exchange failed", "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Verify ID token
	verified, err := h.Provider.VerifyIDToken(ctx, tokens.IDToken, flow.Nonce)
	if err != nil {
		slog.Error("auth: ID token verification failed", "error", err)
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Generate CSRF token for session
	csrfToken, err := oidc.CSRFToken()
	if err != nil {
		slog.Error("auth: failed to generate CSRF token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create session data
	session := oidc.SessionData{
		Subject:  verified.Subject,
		Email:    verified.Email,
		Name:     verified.Name,
		Username: verified.Username,
		Groups:   verified.Groups,
		Expiry:   verified.Expiry.Unix(),
		IssuedAt: time.Now().Unix(),
		CSRF:     csrfToken,
	}

	// Sign session cookie with HMAC
	sessionValue, err := h.signSession(session)
	if err != nil {
		slog.Error("auth: failed to sign session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
	sessionCookie := h.Provider.CookieOptions("/", int(time.Until(verified.Expiry).Seconds()))
	sessionCookie.Name = oidc.CookieSession
	sessionCookie.Value = sessionValue
	http.SetCookie(w, sessionCookie)

	// Set refresh token cookie
	if tokens.RefreshToken != "" {
		// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
		refreshCookie := h.Provider.CookieOptions("/api/v1", int(time.Until(verified.Expiry.Add(24*time.Hour)).Seconds()))
		refreshCookie.Name = oidc.CookieRefresh
		refreshCookie.Value = tokens.RefreshToken
		http.SetCookie(w, refreshCookie)
	}

	// Set CSRF cookie (readable by SPA for X-CSRF-Token header)
	// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
	csrfCookie := h.Provider.CookieOptions("/", int(time.Until(verified.Expiry).Seconds()))
	csrfCookie.Name = oidc.CookieCSRF
	csrfCookie.Value = csrfToken
	csrfCookie.HttpOnly = false // SPA needs to read this
	http.SetCookie(w, csrfCookie)

	// Clear PKCE cookie
	// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
	pkceCookie = h.Provider.CookieOptions("/api/v1/auth/callback", -1)
	pkceCookie.Name = oidc.CookiePKCE
	pkceCookie.Value = ""
	http.SetCookie(w, pkceCookie)

	// Redirect to frontend
	http.Redirect(w, r, "/", http.StatusFound)
}

// MeHandler returns the current user identity.
// GET /api/v1/auth/me
func (h *AuthHandlers) MeHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := middleware.GetIdentity(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	response := map[string]string{
		"email":    identity.Email,
		"name":     identity.Name,
		"username": identity.Username,
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, response)
}

// LogoutHandler logs out the user.
// POST /api/v1/auth/logout
func (h *AuthHandlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Validate CSRF
	if !middleware.RequireCSRF(w, r, h.Config) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}

	// Get refresh token for provider revocation (best effort)
	if refreshCookie, err := r.Cookie(oidc.CookieRefresh); err == nil {
		ctx := r.Context()
		if revokeErr := h.Provider.RevokeToken(ctx, refreshCookie.Value); revokeErr != nil {
			slog.Debug("auth: token revocation failed", "error", revokeErr)
		}
	}

	// Clear all auth cookies
	clearAuthCookies(w, h.Config)

	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]string{"status": "logged_out"})
}

// clearAuthCookies clears all auth cookies.
func clearAuthCookies(w http.ResponseWriter, cfg middleware.AuthConfig) {
	for _, item := range []struct {
		name     string
		path     string
		httpOnly bool
	}{
		{cfg.SessionCookie, "/", true},
		{cfg.RefreshCookie, "/api/v1", true},
		{cfg.CSRFCookie, "/", false},
		{oidc.CookiePKCE, "/api/v1/auth/callback", true},
	} {
		// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
		cookie := &http.Cookie{
			Name:     item.name,
			Value:    "",
			Path:     item.path,
			MaxAge:   -1,
			HttpOnly: item.httpOnly,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.CookieDomain,
		}
		http.SetCookie(w, cookie)
	}
}

// CSRFHandler returns a CSRF token for the SPA.
// GET /api/v1/auth/csrf
func (h *AuthHandlers) CSRFHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := middleware.GetIdentity(r.Context())
	if !ok {
		// For unauthenticated requests, generate a new CSRF token
		token, err := oidc.CSRFToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
		csrfCookie := h.Provider.CookieOptions("/", 3600)
		csrfCookie.Name = oidc.CookieCSRF
		csrfCookie.Value = token
		csrfCookie.HttpOnly = false
		http.SetCookie(w, csrfCookie)

		writeJSON(w, map[string]string{"csrf_token": token})
		return
	}

	// Return existing CSRF token from session
	writeJSON(w, map[string]string{"csrf_token": identity.CSRF})
}
