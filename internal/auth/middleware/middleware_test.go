package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/kubeseal-ui/api/internal/auth/oidc"
)

// csrfTokenVal is built at runtime to avoid a gosec G101 false positive on a
// credential-like literal.
var csrfTokenVal = "valid-csrf-" + "token"

// rotatingProvider is an AuthProvider that rotates refresh tokens the way a strict provider does:
// each token is spendable once, and a retired one is an error rather than a second exchange. It
// counts exchanges and tracks overlap, which is what shows whether the middleware serialised.
type rotatingProvider struct {
	mu        sync.Mutex
	exchanges int
	inFlight  int
	peak      int
	retired   map[string]bool
}

func (p *rotatingProvider) LoginURL(*oidc.FlowState) (string, error) {
	return "", errors.New("not used")
}

func (p *rotatingProvider) ExchangeCode(context.Context, string, string) (*oidc.TokenResponse, error) {
	return nil, errors.New("not used")
}

func (p *rotatingProvider) RevokeToken(context.Context, string) error { return nil }

func (p *rotatingProvider) VerifyIDToken(context.Context, string, string) (*oidc.VerifiedIDToken, error) {
	return &oidc.VerifiedIDToken{
		Subject: "user-123", Email: "user@example.com", Name: "Test User", Username: "testuser",
		Groups: []string{"team-a"}, Expiry: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, nil
}

func (p *rotatingProvider) RefreshTokens(_ context.Context, refreshToken string) (*oidc.TokenResponse, error) {
	p.mu.Lock()
	p.exchanges++
	p.inFlight++
	if p.inFlight > p.peak {
		p.peak = p.inFlight
	}
	spent := p.retired[refreshToken]
	p.retired[refreshToken] = true
	p.mu.Unlock()

	// Held open long enough that overlapping exchanges really do overlap: without it the goroutines
	// may serialise by luck and the test would pass against a middleware that does not serialise.
	time.Sleep(20 * time.Millisecond)

	p.mu.Lock()
	p.inFlight--
	p.mu.Unlock()

	if spent {
		return nil, errors.New("invalid_grant: refresh token already used")
	}
	return &oidc.TokenResponse{RefreshToken: "rotated-" + refreshToken, IDToken: "id-token", ExpiresIn: 3600}, nil
}

func (p *rotatingProvider) counts() (exchanges, peak int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exchanges, p.peak
}

// failingProvider refuses every refresh, which is how a provider outage reaches the middleware.
type failingProvider struct{}

func (failingProvider) LoginURL(*oidc.FlowState) (string, error) {
	return "", errors.New("not used")
}

func (failingProvider) ExchangeCode(context.Context, string, string) (*oidc.TokenResponse, error) {
	return nil, errors.New("not used")
}

func (failingProvider) RevokeToken(context.Context, string) error { return nil }

func (failingProvider) VerifyIDToken(context.Context, string, string) (*oidc.VerifiedIDToken, error) {
	return nil, errors.New("token endpoint unavailable")
}

func (failingProvider) RefreshTokens(context.Context, string) (*oidc.TokenResponse, error) {
	return nil, errors.New("token endpoint unavailable")
}

// testSessionData mirrors the internal sessionCookieData for test setup.
type testSessionData struct {
	SessionData
	Signature string `json:"sig"`
}

// makeTestSession returns a signed, base64-encoded cookie value the middleware accepts.
func makeTestSession(t *testing.T, sess SessionData, signingKey []byte) string {
	t.Helper()
	sig := signSessionCookie(sess, signingKey)
	combined := testSessionData{SessionData: sess, Signature: sig}
	raw, err := json.Marshal(combined)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func makeTestConfig() AuthConfig {
	return AuthConfig{
		SessionCookie:      "kubeseal_session",
		RefreshCookie:      "kubeseal_refresh",
		CSRFCookie:         "kubeseal_csrf",
		CookieSecure:       false,
		CSRFTrustedOrigins: []string{"https://app.example.com"},
		SigningKey:         []byte("test-signing-key"),
	}
}

func validSessionData() SessionData {
	return SessionData{
		Subject:  "user-123",
		Email:    "user@example.com",
		Name:     "Test User",
		Username: "testuser",
		Groups:   []string{"team-a"},
		Expiry:   time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt: time.Now().Unix(),
		CSRF:     "csrf-token-123",
	}
}

func testHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestAuthMiddlewareValidatesSession(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := GetIdentity(r.Context())
		if !ok {
			t.Fatal("identity not in context")
		}
		if id.Email != "user@example.com" {
			t.Errorf("email = %q, want user@example.com", id.Email)
		}
		if id.Username != "testuser" {
			t.Errorf("username = %q, want testuser", id.Username)
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status: want 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestAuthMiddlewareInjectsIdentity(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	sess.Groups = []string{"team-a", "team-b"}
	sess.Username = "different-user"
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	var captured Identity
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	rr := httptest.NewRecorder()
	handler := AuthMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = GetIdentity(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)

	if captured.Username != "different-user" {
		t.Errorf("username = %q, want different-user", captured.Username)
	}
	if len(captured.Groups) != 2 {
		t.Errorf("groups length = %d, want 2", len(captured.Groups))
	}
}

func TestAuthMiddlewareReturns401OnInvalidSession(t *testing.T) {
	cfg := makeTestConfig()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: status = %d, want 401", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req2.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: "not-valid-base64!!!", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rr2 := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("malformed cookie: status = %d, want 401", rr2.Code)
	}

	sess := validSessionData()
	cookieVal := makeTestSession(t, sess, []byte("wrong-signing-key"))
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req3.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rr3 := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusUnauthorized {
		t.Errorf("tampered signature: status = %d, want 401", rr3.Code)
	}
}

func TestAuthMiddlewareReturns401OnExpiredSession(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	sess.Expiry = time.Now().Add(-1 * time.Hour).Unix()
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expired session: status = %d, want 401", rr.Code)
	}
}

// TestAuthMiddlewareTriggersRefresh covers only the no-refresh-token path; a full refresh
// test needs a mock OIDC provider.
func TestAuthMiddlewareTriggersRefresh(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	sess.Expiry = time.Now().Add(-1 * time.Minute).Unix()
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	// No refresh cookie, so the refresh attempt must fail.

	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expired session without refresh: status = %d, want 401", rr.Code)
	}
}

func TestAuthMiddlewareEnforcesCSRF(t *testing.T) {
	cfg := makeTestConfig()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF: status = %d, want 403", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
	rr2 := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("GET without CSRF: status = %d, want 200", rr2.Code)
	}

	csrfToken := csrfTokenVal
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces", nil)
	req3.Header.Set("Origin", "https://app.example.com")
	req3.Header.Set("X-CSRF-Token", csrfToken)
	req3.AddCookie(&http.Cookie{Name: oidc.CookieCSRF, Value: csrfToken, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	rr3 := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF: status = %d, want 200", rr3.Code)
	}
}

func TestAuthMiddlewareRejectsUntrustedOrigin(t *testing.T) {
	cfg := makeTestConfig()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("X-CSRF-Token", csrfTokenVal)
	req.AddCookie(&http.Cookie{Name: oidc.CookieCSRF, Value: csrfTokenVal, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	rr := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("untrusted origin: status = %d, want 403", rr.Code)
	}
}

func TestIdentityFromContext(t *testing.T) {
	id := Identity{
		Subject:  "sub-1",
		Email:    "user@example.com",
		Username: "user",
		Groups:   []string{"team-a"},
	}
	ctx := context.WithValue(context.Background(), identityKey, id)

	got, ok := GetIdentity(ctx)
	if !ok {
		t.Fatal("GetIdentity returned false")
	}
	if got.Subject != id.Subject {
		t.Errorf("subject = %q, want %q", got.Subject, id.Subject)
	}

	got2 := MustGetIdentity(ctx)
	if got2.Subject != id.Subject {
		t.Errorf("MustGetIdentity: subject = %q, want %q", got2.Subject, id.Subject)
	}

	emptyCtx := context.Background()
	_, ok2 := GetIdentity(emptyCtx)
	if ok2 {
		t.Error("GetIdentity on empty context should return false")
	}
}

// refreshRequest builds the request a browser sends while its session is inside the refresh window.
// The cookie value is built by the caller so the concurrency test can hand the same request to every
// goroutine without a helper that calls t.Fatalf off the test's goroutine.
func refreshRequest(sessionCookie, refreshToken, csrfToken string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "kubeseal_session", Value: sessionCookie})
	req.AddCookie(&http.Cookie{Name: "kubeseal_refresh", Value: refreshToken})
	req.AddCookie(&http.Cookie{Name: "kubeseal_csrf", Value: csrfToken})
	return req
}

func okHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := GetIdentity(r.Context())
		if !ok {
			t.Error("identity not in context")
		}
		if id.Email != "user@example.com" {
			t.Errorf("email = %q, want the refreshed identity", id.Email)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func cookieValues(rr *httptest.ResponseRecorder) map[string]string {
	values := map[string]string{}
	for _, c := range rr.Result().Cookies() {
		values[c.Name] = c.Value
	}
	return values
}

// A session inside the refresh window is renewed on the request that carries it, and the rotation
// covers all three cookies: the session, the refresh token the provider replaced, and the CSRF
// cookie whose lifetime came from the token that just expired. Leaving the CSRF cookie behind would
// retire the double-submit anchor while the session lived on — GETs keep working and every write
// starts failing 403, which reads as a permissions bug rather than an expired cookie.
func TestAuthMiddlewareRefreshesANearExpirySession(t *testing.T) {
	provider := &rotatingProvider{retired: map[string]bool{}}
	cfg := makeTestConfig()
	cfg.OIDCProvider = provider

	session := validSessionData()
	session.Expiry = time.Now().Add(time.Minute).Unix()
	req := refreshRequest(makeTestSession(t, session, cfg.SigningKey), "refresh-0", session.CSRF)

	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(okHandler(t)).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}

	values := cookieValues(rr)
	if values[cfg.SessionCookie] == "" {
		t.Error("no session cookie was written")
	}
	if values[cfg.RefreshCookie] != "rotated-refresh-0" {
		t.Errorf("refresh cookie = %q, want rotated-refresh-0", values[cfg.RefreshCookie])
	}
	if values[cfg.CSRFCookie] != session.CSRF {
		t.Errorf("csrf cookie = %q, want the preserved %q", values[cfg.CSRFCookie], session.CSRF)
	}
}

// A page load fires its requests together, so a session near expiry is presented to the middleware
// many times with the same refresh token. A provider that rotates tokens retires that token on the
// first exchange and reads a second use as a replay — the answer to which is often to invalidate the
// whole token family, sending a valid user back to login mid-session. One exchange, and every
// request answered.
func TestAuthMiddlewareSerialisesRefreshAcrossConcurrentRequests(t *testing.T) {
	provider := &rotatingProvider{retired: map[string]bool{}}
	cfg := makeTestConfig()
	cfg.OIDCProvider = provider

	session := validSessionData()
	session.Expiry = time.Now().Add(time.Minute).Unix()
	// Built here, once, so no goroutine calls a helper that reports through t.
	sessionCookie := makeTestSession(t, session, cfg.SigningKey)

	handler := AuthMiddleware(cfg)(okHandler(t))
	const requests = 8
	responses := make([]*httptest.ResponseRecorder, requests)
	var wg sync.WaitGroup
	for i := range responses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, refreshRequest(sessionCookie, "refresh-0", session.CSRF))
			responses[i] = rr
		}(i)
	}
	wg.Wait()

	if exchanges, peak := provider.counts(); exchanges != 1 || peak != 1 {
		t.Errorf("exchanges = %d (peak overlap %d), want 1 and 1", exchanges, peak)
	}
	for i, rr := range responses {
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (body=%s)", i, rr.Code, rr.Body.String())
		}
		if values := cookieValues(rr); values[cfg.RefreshCookie] != "rotated-refresh-0" {
			t.Errorf("request %d: refresh cookie = %q, want the rotated token", i, values[cfg.RefreshCookie])
		}
	}
}

// A refresh that fails while the session still has time left must not end it. The session in hand is
// valid until it expires, so a provider outage becomes a failed refresh that the next request
// retries — not a logout, which is what clearing the cookies here would amount to.
func TestAuthMiddlewareServesAValidSessionWhenTheRefreshFails(t *testing.T) {
	cfg := makeTestConfig()
	cfg.OIDCProvider = &failingProvider{}

	session := validSessionData()
	session.Expiry = time.Now().Add(time.Minute).Unix()
	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(okHandler(t)).ServeHTTP(rr, refreshRequest(makeTestSession(t, session, cfg.SigningKey), "refresh-0", session.CSRF))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a transient refresh failure must not end a valid session (body=%s)", rr.Code, rr.Body.String())
	}
	if values := cookieValues(rr); values[cfg.SessionCookie] != "" {
		t.Error("the session cookie was rewritten by a failed refresh")
	}
}

// The other half of that rule: a session whose payload has expired has nothing left to serve, so a
// refresh that cannot renew it is terminal — the cookies are cleared and the request is refused,
// which is the state the client reads as "log in again".
func TestAuthMiddlewareClearsAnExpiredSessionWhenTheRefreshFails(t *testing.T) {
	cfg := makeTestConfig()
	cfg.OIDCProvider = &failingProvider{}

	session := validSessionData()
	session.Expiry = time.Now().Add(-time.Minute).Unix()
	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(okHandler(t)).ServeHTTP(rr, refreshRequest(makeTestSession(t, session, cfg.SigningKey), "refresh-0", session.CSRF))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	values := cookieValues(rr)
	for _, name := range []string{cfg.SessionCookie, cfg.RefreshCookie} {
		if value, ok := values[name]; !ok || value != "" {
			t.Errorf("cookie %s = %q (present=%v), want it cleared", name, value, ok)
		}
	}
}

// A middleware built without a signing key refuses every request. The alternative — substituting a
// constant key, which is what this used to do — signs sessions with a value that is in the source,
// so a deployment that lost the key would authenticate forged cookies instead of failing.
func TestAuthMiddlewareWithoutASigningKeyRefusesEveryRequest(t *testing.T) {
	cfg := makeTestConfig()
	cfg.SigningKey = nil

	called := false
	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).
		ServeHTTP(rr, refreshRequest("whatever", "refresh-0", "csrf"))

	if called {
		t.Error("the next handler ran without a signing key")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}
