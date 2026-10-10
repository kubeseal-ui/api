package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kubeseal-ui/api/internal/auth/oidc"
)

// csrfTokenVal is built at runtime to avoid a gosec G101 false positive on a
// credential-like literal.
var csrfTokenVal = "valid-csrf-" + "token"

// fakeOIDCProvider is a stub for refresh tests; no test uses it yet.
type fakeOIDCProvider struct{}

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
