// Package handlers provides the authentication HTTP handlers: login, callback, me,
// logout, and csrf.
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
	"github.com/kubeseal-ui/api/internal/metrics"
)

func writeJSON(w http.ResponseWriter, v any) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("auth: failed to encode JSON response", "error", err)
	}
}

// AuthHandlers holds dependencies for auth handlers.
type AuthHandlers struct {
	Provider oidc.AuthProvider
	Config   middleware.AuthConfig
	// SigningKey signs session cookies; in production it comes from a Secret.
	SigningKey []byte
}

func NewAuthHandlers(provider oidc.AuthProvider, cfg middleware.AuthConfig, signingKey []byte) *AuthHandlers {
	return &AuthHandlers{
		Provider:   provider,
		Config:     cfg,
		SigningKey: signingKey,
	}
}

// signSession returns the cookie value: base64(JSON({session, signature})).
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

// sessionCookieData mirrors middleware's private type of the same name; the field names
// and the embedded struct decide the JSON the middleware verifies.
type sessionCookieData struct {
	oidc.SessionData
	Signature string `json:"sig"`
}

func signData(data any, key []byte) (string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal for signing: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// signedFlowState is the PKCE cookie envelope. The signature covers the FlowState fields
// only, so `sig` can travel in the same JSON without being re-signed on verify.
type signedFlowState struct {
	oidc.FlowState
	Signature string `json:"sig,omitempty"`
}

// flowStateBytes is the canonical bytes the verifier re-signs; excluding the signature
// from them is what makes a mutated field invalidate the cookie.
func (s signedFlowState) flowStateBytes() ([]byte, error) {
	return json.Marshal(s.FlowState)
}

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

// verifyFlowState parses the PKCE cookie and checks its signature.
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

func signDataFromRawBytes(raw, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *AuthHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	flow, err := oidc.NewFlowState()
	if err != nil {
		slog.Error("auth: failed to generate flow state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Signing also makes the value cookie-safe: raw JSON cannot survive net/http's cookie
	// transport, which drops invalid bytes like '"'.
	signed, err := signFlowState(*flow, h.SigningKey)
	if err != nil {
		slog.Error("auth: failed to sign flow state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	pkceCookie := &http.Cookie{
		Name:     oidc.CookiePKCE,
		Value:    signed,
		Path:     "/api/v1/auth/callback",
		MaxAge:   5 * 60, // 5 min
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.Config.CookieDomain,
	}
	pkceCookie.Secure = h.Config.CookieSecure
	http.SetCookie(w, pkceCookie)

	loginURL, err := h.Provider.LoginURL(flow)
	if err != nil {
		slog.Error("auth: failed to build login URL", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func (h *AuthHandlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	pkceCookie, err := r.Cookie(oidc.CookiePKCE)
	if err != nil {
		slog.Debug("auth: missing PKCE cookie", "error", err)
		metrics.RecordOIDCAuth("callback_error")
		http.Error(w, "invalid flow state", http.StatusBadRequest)
		return
	}

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

	if validateErr := flow.Validate(); validateErr != nil {
		slog.Debug("auth: flow state validation failed", "error", validateErr)
		http.Error(w, "flow state expired", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if state != flow.State {
		slog.Debug("auth: state mismatch", "expected", flow.State, "got", state)
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		slog.Debug("auth: missing authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	tokens, err := h.Provider.ExchangeCode(ctx, code, flow.PKCEVerifier)
	if err != nil {
		slog.Error("auth: token exchange failed", "error", err)
		metrics.RecordOIDCAuth("failed")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	verified, err := h.Provider.VerifyIDToken(ctx, tokens.IDToken, flow.Nonce)
	if err != nil {
		slog.Error("auth: ID token verification failed", "error", err)
		metrics.RecordOIDCAuth("failed")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	csrfToken, err := oidc.CSRFToken()
	if err != nil {
		slog.Error("auth: failed to generate CSRF token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

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

	sessionValue, err := h.signSession(session)
	if err != nil {
		slog.Error("auth: failed to sign session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sessionCookie := &http.Cookie{
		Name:     oidc.CookieSession,
		Value:    sessionValue,
		Path:     "/",
		MaxAge:   int(time.Until(verified.Expiry).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.Config.CookieDomain,
	}
	sessionCookie.Secure = h.Config.CookieSecure
	http.SetCookie(w, sessionCookie)

	if tokens.RefreshToken != "" {
		refreshCookie := &http.Cookie{
			Name:     oidc.CookieRefresh,
			Value:    tokens.RefreshToken,
			Path:     "/api/v1",
			MaxAge:   int(time.Until(verified.Expiry.Add(24 * time.Hour)).Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Domain:   h.Config.CookieDomain,
		}
		refreshCookie.Secure = h.Config.CookieSecure
		http.SetCookie(w, refreshCookie)
	}

	// HttpOnly is deliberately false: the SPA reads this one for the X-CSRF-Token header.
	csrfCookie := &http.Cookie{ // #nosec G124 -- HttpOnly deliberately false for SPA CSRF readability
		Name:     oidc.CookieCSRF,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   int(time.Until(verified.Expiry).Seconds()),
		HttpOnly: false,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.Config.CookieDomain,
	}
	csrfCookie.Secure = h.Config.CookieSecure
	http.SetCookie(w, csrfCookie)

	pkceCookie = &http.Cookie{
		Name:     oidc.CookiePKCE,
		Value:    "",
		Path:     "/api/v1/auth/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.Config.CookieDomain,
	}
	pkceCookie.Secure = h.Config.CookieSecure
	http.SetCookie(w, pkceCookie)

	metrics.RecordOIDCAuth("success")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *AuthHandlers) MeHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := middleware.GetIdentity(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	response := map[string]any{
		"email":    identity.Email,
		"name":     identity.Name,
		"username": identity.Username,
	}
	// "capabilities" is what the caller holds everywhere; "namespaces" is what it holds in
	// named namespaces. An effective grant is the union. Both keys are always present so a
	// client needs no presence check.
	response["capabilities"] = identity.Capabilities
	namespaces := identity.NamespaceCapabilities
	if namespaces == nil {
		namespaces = map[string][]string{}
	}
	response["namespaces"] = namespaces

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, response)
}

func (h *AuthHandlers) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if !middleware.RequireCSRF(w, r, h.Config) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return
	}

	// Revocation is best effort; a failure is only logged.
	if refreshCookie, err := r.Cookie(oidc.CookieRefresh); err == nil {
		ctx := r.Context()
		if revokeErr := h.Provider.RevokeToken(ctx, refreshCookie.Value); revokeErr != nil {
			slog.Debug("auth: token revocation failed", "error", revokeErr)
		}
	}

	clearAuthCookies(w, h.Config)

	w.WriteHeader(http.StatusOK)
	writeJSON(w, map[string]string{"status": "logged_out"})
}

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
		cookie := &http.Cookie{
			Name:     item.name,
			Value:    "",
			Path:     item.path,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.CookieDomain,
		}
		cookie.HttpOnly = item.httpOnly
		cookie.Secure = cfg.CookieSecure
		http.SetCookie(w, cookie)
	}
}

func (h *AuthHandlers) CSRFHandler(w http.ResponseWriter, r *http.Request) {
	identity, ok := middleware.GetIdentity(r.Context())
	if !ok {
		// Unauthenticated callers get a freshly minted token.
		token, err := oidc.CSRFToken()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		csrfCookie := &http.Cookie{ // #nosec G124 -- HttpOnly deliberately false for SPA CSRF readability
			Name:     oidc.CookieCSRF,
			Value:    token,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: false,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Domain:   h.Config.CookieDomain,
		}
		csrfCookie.Secure = h.Config.CookieSecure
		http.SetCookie(w, csrfCookie)

		writeJSON(w, map[string]string{"csrf_token": token})
		return
	}

	writeJSON(w, map[string]string{"csrf_token": identity.CSRF})
}
