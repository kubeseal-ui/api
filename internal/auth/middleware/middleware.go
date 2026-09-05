// Package middleware provides the authentication middleware for the kubeseal-ui API.
//
// The middleware:
// 1. Validates the session cookie and extracts identity
// 2. Injects identity into request context
// 3. Handles automatic token refresh before session expiry
// 4. Enforces CSRF validation on state-changing requests
package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/kubeseal-ui/api/internal/auth/oidc"
)

// Context keys
type ctxKey int

const (
	identityKey ctxKey = iota
)

// Identity represents the authenticated user identity.
type Identity struct {
	Subject      string
	Email        string
	Name         string
	Username     string
	Groups       []string
	Expiry       time.Time
	CSRF         string
	Capabilities []string
}

// WithIdentity adds an authenticated identity to a request context.
// It is used by the router after session validation and by focused handler tests.
func WithIdentity(r *http.Request, id Identity) *http.Request {
	ctx := context.WithValue(r.Context(), identityKey, id)
	return r.WithContext(ctx)
}

// GetIdentity retrieves the identity from the request context.
func GetIdentity(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok
}

// MustGetIdentity retrieves the identity or panics (for handlers that require auth).
func MustGetIdentity(ctx context.Context) Identity {
	id, ok := GetIdentity(ctx)
	if !ok {
		panic("identity not found in context - auth middleware must be applied")
	}
	return id
}

// AuthConfig holds configuration for the auth middleware.
type AuthConfig struct {
	OIDCProvider       oidc.AuthProvider
	SessionCookie      string
	RefreshCookie      string
	CSRFCookie         string
	CookieSecure       bool
	CookieDomain       string
	CSRFTrustedOrigins []string
	// SigningKey is the HMAC key used to sign/verify session cookies.
	SigningKey []byte
	// ResolveCapabilities maps normalized OIDC groups to effective capabilities.
	ResolveCapabilities func([]string) []string
}

// DefaultAuthConfig returns a default auth config for testing.
func DefaultAuthConfig(provider oidc.AuthProvider) AuthConfig {
	return AuthConfig{
		OIDCProvider:       provider,
		SessionCookie:      oidc.CookieSession,
		RefreshCookie:      oidc.CookieRefresh,
		CSRFCookie:         oidc.CookieCSRF,
		CookieSecure:       false, // Tests use insecure
		CookieDomain:       "",
		CSRFTrustedOrigins: []string{"https://app.example.com"},
		SigningKey:         []byte("test-signing-key"),
	}
}

// sessionCookieData is the decoded session cookie.
type sessionCookieData struct {
	SessionData
	Signature string `json:"sig"`
}

// SessionData mirrors oidc.SessionData but with Expiry as time.Time for internal use.
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

// signSessionCookie creates an HMAC signature for the session cookie.
func signSessionCookie(data SessionData, secret []byte) string {
	raw, err := json.Marshal(data)
	if err != nil {
		// This should never fail for our struct, but handle it.
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifySessionCookie verifies the HMAC signature and expiry.
func verifySessionCookie(data SessionData, sig string, secret []byte) error {
	expected := signSessionCookie(data, secret)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return errors.New("invalid session signature")
	}
	if time.Now().Unix() > data.Expiry {
		return errors.New("session expired")
	}
	return nil
}

// AuthMiddleware returns middleware that validates the session cookie.
func AuthMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	signingKey := cfg.SigningKey
	if len(signingKey) == 0 {
		signingKey = []byte("dev-signing-key-change-in-production")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookieData, ok := extractAndValidateSession(w, r, cfg, signingKey)
			if !ok {
				return
			}

			scheduleAsyncRefresh(r, cookieData.Expiry, cfg, signingKey)

			// Build identity
			identity := buildIdentity(cookieData, cfg.ResolveCapabilities)

			// Add identity to context
			ctx := context.WithValue(r.Context(), identityKey, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAndValidateSession extracts and validates the session cookie.
// Returns the cookie data and true if valid, or writes error response and returns false.
func extractAndValidateSession(w http.ResponseWriter, r *http.Request, cfg AuthConfig, signingKey []byte) (sessionCookieData, bool) {
	// Try to get session cookie
	sessionCookie, err := r.Cookie(cfg.SessionCookie)
	if err != nil {
		slog.Debug("auth: no session cookie", "error", err)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	// Decode base64-encoded signed session cookie
	raw, err := base64.RawURLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		slog.Debug("auth: invalid session cookie encoding", "error", err)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	// Parse session cookie (JSON with signature)
	var cookieData sessionCookieData
	if err := json.Unmarshal(raw, &cookieData); err != nil {
		slog.Debug("auth: invalid session cookie format", "error", err)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	// Verify signature and expiry
	if err := verifySessionCookie(cookieData.SessionData, cookieData.Signature, signingKey); err != nil {
		slog.Debug("auth: session verification failed", "error", err)
		// Check if session expired — attempt refresh
		if err.Error() == "session expired" {
			if refreshed, ok := attemptRefresh(w, r, cfg, signingKey); ok {
				return refreshed, true
			}
		}
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	return cookieData, true
}

// attemptRefresh tries to refresh the session using the refresh token.
func attemptRefresh(w http.ResponseWriter, r *http.Request, cfg AuthConfig, signingKey []byte) (sessionCookieData, bool) {
	if cfg.OIDCProvider == nil || len(signingKey) == 0 {
		if w != nil {
			clearAuthCookies(w, cfg)
		}
		return sessionCookieData{}, false
	}
	refreshCookie, err := r.Cookie(cfg.RefreshCookie)
	if err != nil {
		return sessionCookieData{}, false
	}

	ctx := r.Context()
	tokens, err := cfg.OIDCProvider.RefreshTokens(ctx, refreshCookie.Value)
	if err != nil {
		slog.Debug("auth: token refresh failed", "error", err)
		// Clear cookies on refresh failure
		if w != nil {
			clearAuthCookies(w, cfg)
		}
		return sessionCookieData{}, false
	}

	// Verify new ID token
	// A refreshed ID token must still pass the provider's normal issuer,
	// audience, signature, expiry, and claim validation. Refresh responses do
	// not carry the original login nonce, so nonce validation is performed by
	// the provider only when a nonce is supplied.
	verified, err := cfg.OIDCProvider.VerifyIDToken(ctx, tokens.IDToken, "")
	if err != nil {
		slog.Debug("auth: refreshed ID token verification failed", "error", err)
		if w != nil {
			clearAuthCookies(w, cfg)
		}
		return sessionCookieData{}, false
	}

	// Get existing CSRF from session cookie to preserve it
	existingCSRF := ""
	if sc, cerr := r.Cookie(cfg.SessionCookie); cerr == nil {
		raw, decErr := base64.RawURLEncoding.DecodeString(sc.Value)
		if decErr == nil {
			var cookieData sessionCookieData
			if json.Unmarshal(raw, &cookieData) == nil {
				existingCSRF = cookieData.CSRF
			}
		}
	}

	// Create new session data
	newSession := SessionData{
		Subject:  verified.Subject,
		Email:    verified.Email,
		Name:     verified.Name,
		Username: verified.Username,
		Groups:   verified.Groups,
		Expiry:   verified.Expiry.Unix(),
		IssuedAt: time.Now().Unix(),
		CSRF:     existingCSRF, // Keep existing CSRF token
	}

	// Sign and set new session cookie
	sig := signSessionCookie(newSession, signingKey)
	newCookieData := sessionCookieData{
		SessionData: newSession,
		Signature:   sig,
	}

	cookieJSON, err := json.Marshal(newCookieData)
	if err != nil {
		slog.Debug("auth: failed to marshal new session", "error", err)
		return sessionCookieData{}, false
	}
	encodedSession := base64.RawURLEncoding.EncodeToString(cookieJSON)

	// Set cookies
	if w != nil {
		// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
		sessionCookie := cfg.OIDCProvider.CookieOptions("/", int(time.Until(verified.Expiry).Seconds())) //nolint:gosec
		sessionCookie.Name = cfg.SessionCookie
		sessionCookie.Value = encodedSession
		http.SetCookie(w, sessionCookie)

		if tokens.RefreshToken != "" {
			// nolint:gosec // Cookie security flags configured via cfg.CookieSecure
						refreshCookie := cfg.OIDCProvider.CookieOptions("/api/v1", int(time.Until(verified.Expiry.Add(24*time.Hour)).Seconds())) //nolint:gosec
			refreshCookie.Name = cfg.RefreshCookie
			refreshCookie.Value = tokens.RefreshToken
			http.SetCookie(w, refreshCookie)
		}
	}

	return newCookieData, true
}

// scheduleAsyncRefresh schedules a background token refresh if expiry is near.
func scheduleAsyncRefresh(r *http.Request, expiry int64, cfg AuthConfig, signingKey []byte) {
	if time.Until(time.Unix(expiry, 0)) >= 5*time.Minute {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		_, _ = attemptRefresh(nil, r.WithContext(ctx), cfg, signingKey)
	}()
}

// buildIdentity creates an Identity from session cookie data.
func buildIdentity(cookieData sessionCookieData, resolve ...func([]string) []string) Identity {
	caps := []string(nil)
	if len(resolve) > 0 && resolve[0] != nil {
		caps = resolve[0](cookieData.Groups)
	}
	return Identity{
		Subject: cookieData.Subject, Email: cookieData.Email, Name: cookieData.Name,
		Username: cookieData.Username, Groups: cookieData.Groups,
		Expiry: time.Unix(cookieData.Expiry, 0), CSRF: cookieData.CSRF,
		Capabilities: caps,
	}
}

// clearAuthCookies clears all auth cookies.
func clearAuthCookies(w http.ResponseWriter, cfg AuthConfig) {
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

// CSRFMiddleware returns middleware that validates CSRF tokens on state-changing requests.
func CSRFMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			csrfCookie, err := r.Cookie(cfg.CSRFCookie)
			if err != nil {
				slog.Debug("csrf: no CSRF cookie")
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}

			csrfHeader := extractCSRFToken(r)
			if csrfHeader == "" {
				slog.Debug("csrf: no CSRF token in request")
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}

			if !validateCSRFToken(csrfCookie.Value, csrfHeader) {
				slog.Debug("csrf: token mismatch")
				http.Error(w, "CSRF validation failed", http.StatusForbidden)
				return
			}

			if r.Header.Get("Origin") == "" || !isTrustedOrigin(r.Header.Get("Origin"), cfg.CSRFTrustedOrigins) {
				slog.Debug("csrf: untrusted or missing origin")
				http.Error(w, "CSRF validation failed: untrusted origin", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isSafeMethod returns true for HTTP methods that don't require CSRF validation.
func isSafeMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

// extractCSRFToken gets the CSRF token from header or form field.
func extractCSRFToken(r *http.Request) string {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.FormValue("csrf_token")
	}
	return token
}

// validateCSRFToken compares the CSRF token from cookie with the one from request.
func validateCSRFToken(cookieToken, headerToken string) bool {
	return hmac.Equal([]byte(cookieToken), []byte(headerToken))
}

// isTrustedOrigin checks if the origin is in the trusted origins list.
func isTrustedOrigin(origin string, trustedOrigins []string) bool {
	if origin == "" {
		return false
	}
	for _, trusted := range trustedOrigins {
		if origin == trusted {
			return true
		}
	}
	return false
}

// RequireAuth is a helper for handlers that need authentication.
// It returns the identity or writes a 401 response.
func RequireAuth(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, ok := GetIdentity(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return Identity{}, false
	}
	return id, true
}

// RequireCSRF is a helper for handlers that need CSRF validation.
// It validates the CSRF token and returns true if valid.
func RequireCSRF(w http.ResponseWriter, r *http.Request, cfg AuthConfig) bool {
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
		return true
	}

	csrfCookie, err := r.Cookie(cfg.CSRFCookie)
	if err != nil {
		return false
	}

	csrfHeader := r.Header.Get("X-CSRF-Token")
	if csrfHeader == "" {
		csrfHeader = r.FormValue("csrf_token")
	}
	if csrfHeader == "" {
		return false
	}
	if !hmac.Equal([]byte(csrfCookie.Value), []byte(csrfHeader)) {
		return false
	}
	origin := r.Header.Get("Origin")
	return origin != "" && isTrustedOrigin(origin, cfg.CSRFTrustedOrigins)
}
