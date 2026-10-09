// Package middleware provides the authentication middleware: it validates the session
// cookie, injects the identity into the request context, refreshes near-expiry sessions,
// and enforces CSRF on state-changing requests.
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

type ctxKey int

const (
	identityKey ctxKey = iota
)

// CapabilityGrants is an identity's resolved capabilities: Global applies in every
// namespace, Scoped only in the namespaces it names. A namespace absent from Scoped is not
// denied — the global set still applies there.
type CapabilityGrants struct {
	Global []string
	Scoped map[string][]string
}

type Identity struct {
	Subject      string
	Email        string
	Name         string
	Username     string
	Groups       []string
	Expiry       time.Time
	CSRF         string
	Capabilities []string
	// NamespaceCapabilities is keyed by namespace. Read it through CapabilitiesFor: the
	// effective set in a namespace is the scoped one unioned with the global.
	NamespaceCapabilities map[string][]string
}

// CapabilitiesFor returns the global grants plus the ones scoped to that namespace.
func (i Identity) CapabilitiesFor(namespace string) []string {
	return unionCapabilities(i.Capabilities, i.NamespaceCapabilities[namespace])
}

func (i Identity) HasCapabilityIn(namespace, capability string) bool {
	return containsCapability(i.CapabilitiesFor(namespace), capability)
}

// HasCapabilityAnywhere reports whether the identity holds a capability anywhere. It is a
// pre-filter for requests whose namespace is not known yet, and must never authorize a
// specific namespace: "holds secret:seal in payments" does not answer for development.
func (i Identity) HasCapabilityAnywhere(capability string) bool {
	if containsCapability(i.Capabilities, capability) {
		return true
	}
	for _, scoped := range i.NamespaceCapabilities {
		if containsCapability(scoped, capability) {
			return true
		}
	}
	return false
}

// unionCapabilities unions the lists in order, dropping duplicates. Nil in, nil out: an
// identity with no grants carries no allocated empty slice through every request.
func unionCapabilities(lists ...[]string) []string {
	var result []string
	seen := map[string]bool{}
	for _, list := range lists {
		for _, capability := range list {
			if seen[capability] {
				continue
			}
			seen[capability] = true
			result = append(result, capability)
		}
	}
	return result
}

func containsCapability(capabilities []string, capability string) bool {
	for _, candidate := range capabilities {
		if candidate == capability {
			return true
		}
	}
	return false
}

// WithIdentity adds an authenticated identity to a request context.
func WithIdentity(r *http.Request, id Identity) *http.Request {
	ctx := context.WithValue(r.Context(), identityKey, id)
	return r.WithContext(ctx)
}

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

type AuthConfig struct {
	OIDCProvider       oidc.AuthProvider
	SessionCookie      string
	RefreshCookie      string
	CSRFCookie         string
	CookieSecure       bool
	CookieDomain       string
	CSRFTrustedOrigins []string
	SigningKey         []byte
	// ResolveCapabilities maps normalized OIDC groups to effective capabilities.
	ResolveCapabilities func([]string) CapabilityGrants
}

// DefaultAuthConfig returns a config for tests.
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

type sessionCookieData struct {
	SessionData
	Signature string `json:"sig"`
}

// SessionData is the JSON payload of the session cookie.
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

func signSessionCookie(data SessionData, secret []byte) string {
	raw, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

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

			identity := buildIdentity(cookieData, cfg.ResolveCapabilities)

			ctx := context.WithValue(r.Context(), identityKey, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAndValidateSession returns the cookie data, or writes 401 and returns false.
func extractAndValidateSession(w http.ResponseWriter, r *http.Request, cfg AuthConfig, signingKey []byte) (sessionCookieData, bool) {
	sessionCookie, err := r.Cookie(cfg.SessionCookie)
	if err != nil {
		slog.Debug("auth: no session cookie", "error", err)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	raw, err := base64.RawURLEncoding.DecodeString(sessionCookie.Value)
	if err != nil {
		slog.Debug("auth: invalid session cookie encoding", "error", err)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	var cookieData sessionCookieData
	if err := json.Unmarshal(raw, &cookieData); err != nil {
		slog.Debug("auth: invalid session cookie format", "error", err)
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	if err := verifySessionCookie(cookieData.SessionData, cookieData.Signature, signingKey); err != nil {
		slog.Debug("auth: session verification failed", "error", err)
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
		if w != nil {
			clearAuthCookies(w, cfg)
		}
		return sessionCookieData{}, false
	}

	// A refreshed ID token still passes issuer, audience, signature, expiry, and claim
	// validation; refresh responses carry no login nonce, so nonce checking is skipped.
	verified, err := cfg.OIDCProvider.VerifyIDToken(ctx, tokens.IDToken, "")
	if err != nil {
		slog.Debug("auth: refreshed ID token verification failed", "error", err)
		if w != nil {
			clearAuthCookies(w, cfg)
		}
		return sessionCookieData{}, false
	}

	// Preserve the existing CSRF token across the refresh.
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

	newSession := SessionData{
		Subject:  verified.Subject,
		Email:    verified.Email,
		Name:     verified.Name,
		Username: verified.Username,
		Groups:   verified.Groups,
		Expiry:   verified.Expiry.Unix(),
		IssuedAt: time.Now().Unix(),
		CSRF:     existingCSRF,
	}

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

	if w != nil {
		sessionCookie := &http.Cookie{
			Name:     cfg.SessionCookie,
			Value:    encodedSession,
			Path:     "/",
			MaxAge:   int(time.Until(verified.Expiry).Seconds()),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.CookieDomain,
		}
		sessionCookie.Secure = cfg.CookieSecure
		http.SetCookie(w, sessionCookie)

		if tokens.RefreshToken != "" {
			refreshCookie := &http.Cookie{
				Name:     cfg.RefreshCookie,
				Value:    tokens.RefreshToken,
				Path:     "/api/v1",
				MaxAge:   int(time.Until(verified.Expiry.Add(24 * time.Hour)).Seconds()),
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				Domain:   cfg.CookieDomain,
			}
			refreshCookie.Secure = cfg.CookieSecure
			http.SetCookie(w, refreshCookie)
		}
	}

	return newCookieData, true
}

// scheduleAsyncRefresh refreshes in the background when the session is within 5 minutes of
// expiry.
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

func buildIdentity(cookieData sessionCookieData, resolve ...func([]string) CapabilityGrants) Identity {
	var grants CapabilityGrants
	if len(resolve) > 0 && resolve[0] != nil {
		grants = resolve[0](cookieData.Groups)
	}
	return Identity{
		Subject: cookieData.Subject, Email: cookieData.Email, Name: cookieData.Name,
		Username: cookieData.Username, Groups: cookieData.Groups,
		Expiry: time.Unix(cookieData.Expiry, 0), CSRF: cookieData.CSRF,
		Capabilities: grants.Global, NamespaceCapabilities: grants.Scoped,
	}
}

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

func isSafeMethod(method string) bool {
	return method == "GET" || method == "HEAD" || method == "OPTIONS"
}

func extractCSRFToken(r *http.Request) string {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = r.FormValue("csrf_token")
	}
	return token
}

func validateCSRFToken(cookieToken, headerToken string) bool {
	return hmac.Equal([]byte(cookieToken), []byte(headerToken))
}

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

// RequireAuth returns the identity or writes 401.
func RequireAuth(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, ok := GetIdentity(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return Identity{}, false
	}
	return id, true
}

// RequireCSRF validates the CSRF token, returning false when it is missing or the origin
// is untrusted.
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
