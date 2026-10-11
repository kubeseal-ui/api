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
	"sync"
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
		// Fail closed rather than substitute a key. A constant compiled into the binary signs a
		// session anyone can forge, and a deployment that forgot the key must serve 401 rather than
		// authenticate on a secret that is in the source. Logged once, at construction, because
		// every request takes this path.
		slog.Error("auth: no session signing key configured; refusing every request")
		return func(http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
			})
		}
	}
	gate := newRefreshGate()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookieData, ok := extractAndValidateSession(w, r, cfg, signingKey, gate)
			if !ok {
				return
			}

			identity := buildIdentity(cookieData, cfg.ResolveCapabilities)

			ctx := context.WithValue(r.Context(), identityKey, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAndValidateSession returns the cookie data, or writes 401 and returns false. A session
// inside the refresh window is renewed here, before the handler and the ACL checks run.
func extractAndValidateSession(w http.ResponseWriter, r *http.Request, cfg AuthConfig, signingKey []byte, gate *refreshGate) (sessionCookieData, bool) {
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
			// A cookie that outlived its payload — a client ignoring MaxAge, or clock skew. The
			// session is gone and only a refresh can revive it, so this one is terminal.
			if refreshed, ok := attemptRefresh(w, r, cfg, signingKey, gate); ok {
				return refreshed, true
			}
			clearAuthCookies(w, cfg)
		}
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return sessionCookieData{}, false
	}

	// Renewal runs while the session is still in force, so a refresh that fails on a transient
	// provider error does not end a session that still has time left: the request is served on the
	// session in hand and the next one tries again. Cleared cookies and 401 are for the session
	// above, which has nothing left to renew.
	if time.Until(time.Unix(cookieData.Expiry, 0)) < sessionRefreshWindow {
		if refreshed, ok := attemptRefresh(w, r, cfg, signingKey, gate); ok {
			return refreshed, true
		}
	}

	return cookieData, true
}

// sessionRefreshWindow is how long before expiry a session is renewed.
const sessionRefreshWindow = 5 * time.Minute

// refreshGate keeps one exchange per spent refresh token, shared by every request presenting it. A
// browser whose session is inside the refresh window fires a page of requests carrying that token,
// and a provider that rotates refresh tokens retires it on the first exchange — the others would
// present a spent token, which such providers read as a replay of the whole token family and answer
// by killing it. The first caller performs the exchange; the rest adopt its result, which is the same
// identity, the same CSRF token, and a cookie signed with the same key.
type refreshGate struct {
	mu      sync.Mutex
	entries map[string]*refreshEntry
}

// refreshGrace is how long a completed exchange stays available to requests that arrive with the
// token it spent.
//
// This is about more than the requests waiting while the exchange runs. A page load fires its
// requests together, so most of them reach the middleware *after* the exchange has finished and
// still carry the pre-refresh cookie, because the browser only learns the new one when the first
// response lands. Every one of those would present a spent token and provoke exactly the replay the
// gate exists to prevent, from the requests that arrived a moment too late.
const refreshGrace = 60 * time.Second

// refreshEntry is one exchange, shared by the requests presenting the token it spends. It is in
// flight until settle publishes the outcome, and answers late arrivals until it expires.
type refreshEntry struct {
	done    chan struct{}
	outcome *refreshOutcome
	expires time.Time
}

func newRefreshGate() *refreshGate {
	return &refreshGate{entries: map[string]*refreshEntry{}}
}

// enter returns the entry for a token — in flight, recently settled, or one this caller now leads.
func (g *refreshGate) enter(key string) (entry *refreshEntry, lead bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	for k, e := range g.entries {
		// Swept here rather than on a timer, so the map holds only the refreshes of the last grace
		// period and nothing needs stopping when the process shuts down.
		if !e.expires.IsZero() && now.After(e.expires) {
			delete(g.entries, k)
		}
	}
	if existing, ok := g.entries[key]; ok {
		return existing, false
	}
	entry = &refreshEntry{done: make(chan struct{})}
	g.entries[key] = entry
	return entry, true
}

// settle publishes the outcome to everyone waiting on this token and keeps it for the grace period.
// A failed exchange is published too: the waiter's answer to a spent token is the same as the
// leader's, and retrying an invalid_grant is what the contract forbids.
func (g *refreshGate) settle(key string, entry *refreshEntry, outcome *refreshOutcome) {
	g.mu.Lock()
	entry.outcome = outcome
	entry.expires = time.Now().Add(refreshGrace)
	g.mu.Unlock()
	close(entry.done)
}

// refreshGateKey hashes the refresh token so the token itself is not held in the map.
func refreshGateKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// refreshOutcome is the result of one exchange, shared with the requests that waited on it: the
// signed session, the token that replaced the spent one, and the expiry every rotated cookie
// derives from. Each participant writes the same cookies, so it does not matter which response the
// browser commits last.
type refreshOutcome struct {
	session      sessionCookieData
	cookieValue  string
	refreshToken string
	csrf         string
	expiry       time.Time
}

// attemptRefresh spends the session's refresh token and, on success, writes the rotated cookies to
// this response. A failure leaves every cookie untouched and reports false: what an unrenewable
// session means is the caller's decision, and it differs between a session still in force and one
// that has already expired.
//
// The exchange runs on the request's own goroutine, inside the request deadline, because a rotated
// cookie needs a response to be written to — a refresh the client never receives is not a refresh.
func attemptRefresh(w http.ResponseWriter, r *http.Request, cfg AuthConfig, signingKey []byte, gate *refreshGate) (sessionCookieData, bool) {
	if cfg.OIDCProvider == nil || len(signingKey) == 0 {
		return sessionCookieData{}, false
	}
	refreshCookie, err := r.Cookie(cfg.RefreshCookie)
	if err != nil {
		// No refresh token to spend (a provider that issues none, or a cleared cookie): the
		// session serves until it expires.
		return sessionCookieData{}, false
	}

	key := refreshGateKey(refreshCookie.Value)
	entry, lead := gate.enter(key)
	if !lead {
		// Another request has spent — or is spending — this token. Waiting for its result rather
		// than presenting the token again is the point of the gate: a rotating provider reads the
		// second use of a spent token as a replay.
		select {
		case <-entry.done:
		case <-r.Context().Done():
			return sessionCookieData{}, false
		}
		if entry.outcome == nil {
			return sessionCookieData{}, false
		}
		writeRefreshCookies(w, cfg, *entry.outcome)
		return entry.outcome.session, true
	}

	outcome := exchangeRefreshToken(r, cfg, signingKey, refreshCookie.Value)
	// Settled before this caller writes its own cookies, so waiters are released as soon as the
	// exchange is decided.
	gate.settle(key, entry, outcome)
	if outcome == nil {
		return sessionCookieData{}, false
	}
	writeRefreshCookies(w, cfg, *outcome)
	return outcome.session, true
}

// exchangeRefreshToken spends one refresh token at the provider and verifies what comes back. A nil
// result means the refresh failed, and the caller answers 401 and clears the session cookies.
func exchangeRefreshToken(r *http.Request, cfg AuthConfig, signingKey []byte, refreshToken string) *refreshOutcome {
	ctx := r.Context()
	tokens, err := cfg.OIDCProvider.RefreshTokens(ctx, refreshToken)
	if err != nil {
		slog.Debug("auth: token refresh failed", "error", err)
		return nil
	}

	// A refreshed ID token still passes issuer, audience, signature, expiry, and claim
	// validation; refresh responses carry no login nonce, so nonce checking is skipped.
	verified, err := cfg.OIDCProvider.VerifyIDToken(ctx, tokens.IDToken, "")
	if err != nil {
		slog.Debug("auth: refreshed ID token verification failed", "error", err)
		return nil
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

	newCookieData := sessionCookieData{
		SessionData: newSession,
		Signature:   signSessionCookie(newSession, signingKey),
	}

	cookieJSON, err := json.Marshal(newCookieData)
	if err != nil {
		slog.Debug("auth: failed to marshal new session", "error", err)
		return nil
	}

	return &refreshOutcome{
		session:      newCookieData,
		cookieValue:  base64.RawURLEncoding.EncodeToString(cookieJSON),
		refreshToken: tokens.RefreshToken,
		csrf:         existingCSRF,
		expiry:       verified.Expiry,
	}
}

// writeRefreshCookies writes the rotation the contract calls for: the session, the refresh token
// that replaced the spent one, and the CSRF cookie.
//
// The CSRF cookie is rewritten even though its value does not change. Its lifetime was set from the
// token that just expired, so leaving it alone would retire the double-submit anchor while the
// session it belongs to lives on — GETs keep working and every state-changing request starts
// failing 403, which reads as a permissions bug rather than an expired cookie.
func writeRefreshCookies(w http.ResponseWriter, cfg AuthConfig, outcome refreshOutcome) {
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.SessionCookie,
		Value:    outcome.cookieValue,
		Path:     "/",
		MaxAge:   int(time.Until(outcome.expiry).Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   cfg.CookieDomain,
	})
	if outcome.refreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.RefreshCookie,
			Value:    outcome.refreshToken,
			Path:     "/api/v1",
			MaxAge:   int(time.Until(outcome.expiry.Add(24 * time.Hour)).Seconds()),
			HttpOnly: true,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			Domain:   cfg.CookieDomain,
		})
	}
	if outcome.csrf == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly deliberately false for SPA CSRF readability
		Name:     cfg.CSRFCookie,
		Value:    outcome.csrf,
		Path:     "/",
		MaxAge:   int(time.Until(outcome.expiry).Seconds()),
		HttpOnly: false,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   cfg.CookieDomain,
	})
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
