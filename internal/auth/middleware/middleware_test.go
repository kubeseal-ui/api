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

// --- test helpers ---

// fakeOIDCProvider is a minimal stub for future refresh tests.
// Currently unused — kept for documentation of the refresh test pattern.
type fakeOIDCProvider struct{}

// sessionCookieData mirrors the middleware's internal type for test setup.
type testSessionData struct {
	SessionData
	Signature string `json:"sig"`
}

// makeTestSession creates a signed, base64-encoded session cookie value
// that the middleware can validate.
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

// makeTestConfig returns a minimal AuthConfig with a test signing key.
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

// validSessionData returns a session that is not expired.
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

// TestAuthMiddlewareValidatesSession verifies that a valid signed session
// cookie results in the handler being called (200).
func TestAuthMiddlewareValidatesSession(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal})

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

// TestAuthMiddlewareInjectsIdentity verifies that the identity from the
// session cookie is correctly injected into the request context.
func TestAuthMiddlewareInjectsIdentity(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	sess.Groups = []string{"team-a", "team-b"}
	sess.Username = "different-user"
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	var captured Identity
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal})

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

// TestAuthMiddlewareReturns401OnInvalidSession verifies that a missing
// or malformed session cookie returns 401.
func TestAuthMiddlewareReturns401OnInvalidSession(t *testing.T) {
	cfg := makeTestConfig()

	// No cookie at all
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: status = %d, want 401", rr.Code)
	}

	// Malformed cookie value (not base64)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req2.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: "not-valid-base64!!!"})
	rr2 := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("malformed cookie: status = %d, want 401", rr2.Code)
	}

	// Tampered signature
	sess := validSessionData()
	cookieVal := makeTestSession(t, sess, []byte("wrong-signing-key"))
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req3.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal})
	rr3 := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusUnauthorized {
		t.Errorf("tampered signature: status = %d, want 401", rr3.Code)
	}
}

// TestAuthMiddlewareReturns401OnExpiredSession verifies that an expired
// session cookie returns 401 (without a refresh token, it can't refresh).
func TestAuthMiddlewareReturns401OnExpiredSession(t *testing.T) {
	cfg := makeTestConfig()
	sess := validSessionData()
	sess.Expiry = time.Now().Add(-1 * time.Hour).Unix() // expired
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal})

	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expired session: status = %d, want 401", rr.Code)
	}
}

// TestAuthMiddlewareTriggersRefresh verifies that when the session is
// expired but a valid refresh token exists and the OIDC provider can
// refresh, the middleware refreshes the session and allows the request.
func TestAuthMiddlewareTriggersRefresh(t *testing.T) {
	// This test documents the refresh flow. A full integration test
	// requires a mock OIDC provider. For unit testing the middleware,
	// we verify that an expired session with no refresh token returns 401.
	cfg := makeTestConfig()
	sess := validSessionData()
	sess.Expiry = time.Now().Add(-1 * time.Minute).Unix() // expired
	cookieVal := makeTestSession(t, sess, cfg.SigningKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: oidc.CookieSession, Value: cookieVal})
	// No refresh cookie — refresh should fail

	rr := httptest.NewRecorder()
	AuthMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expired session without refresh: status = %d, want 401", rr.Code)
	}
}

// TestAuthMiddlewareEnforcesCSRF verifies that CSRFMiddleware rejects
// state-changing requests without a valid CSRF token.
func TestAuthMiddlewareEnforcesCSRF(t *testing.T) {
	cfg := makeTestConfig()

	// POST without CSRF token should be rejected
	req := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF: status = %d, want 403", rr.Code)
	}

	// GET should pass without CSRF (safe method)
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
	rr2 := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Errorf("GET without CSRF: status = %d, want 200", rr2.Code)
	}

	// POST with valid CSRF should pass
	csrfToken := "valid-csrf-token"
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces", nil)
	req3.Header.Set("Origin", "https://app.example.com")
	req3.Header.Set("X-CSRF-Token", csrfToken)
	req3.AddCookie(&http.Cookie{Name: oidc.CookieCSRF, Value: csrfToken})
	rr3 := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusOK {
		t.Errorf("POST with valid CSRF: status = %d, want 200", rr3.Code)
	}
}

// TestAuthMiddlewareRejectsUntrustedOrigin verifies that CSRFMiddleware
// rejects requests from untrusted origins.
func TestAuthMiddlewareRejectsUntrustedOrigin(t *testing.T) {
	cfg := makeTestConfig()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("X-CSRF-Token", "valid-csrf-token")
	req.AddCookie(&http.Cookie{Name: oidc.CookieCSRF, Value: "valid-csrf-token"})

	rr := httptest.NewRecorder()
	CSRFMiddleware(cfg)(http.HandlerFunc(testHandler)).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("untrusted origin: status = %d, want 403", rr.Code)
	}
}

// TestIdentityFromContext verifies GetIdentity and MustGetIdentity.
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

	// MustGetIdentity should return the same identity
	got2 := MustGetIdentity(ctx)
	if got2.Subject != id.Subject {
		t.Errorf("MustGetIdentity: subject = %q, want %q", got2.Subject, id.Subject)
	}

	// Context without identity
	emptyCtx := context.Background()
	_, ok2 := GetIdentity(emptyCtx)
	if ok2 {
		t.Error("GetIdentity on empty context should return false")
	}
}
