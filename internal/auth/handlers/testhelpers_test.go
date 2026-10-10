package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/auth/oidc"
)

type fakeProvider struct {
	loginURL    string
	loginErr    error
	exchange    *oidc.TokenResponse
	exchangeErr error
	verified    *oidc.VerifiedIDToken
	verifyErr   error
	refresh     *oidc.TokenResponse
	refreshErr  error
	revokeErr   error
	cookies     bool
}

func (f *fakeProvider) LoginURL(_ *oidc.FlowState) (string, error) {
	if f.loginURL == "" {
		return "https://auth.example.com/authorize?state=x", nil
	}
	return f.loginURL, f.loginErr
}
func (f *fakeProvider) ExchangeCode(_ context.Context, _, _ string) (*oidc.TokenResponse, error) {
	if f.exchange != nil {
		return f.exchange, f.exchangeErr
	}
	return &oidc.TokenResponse{IDToken: "id-token", RefreshToken: "refresh-token", AccessToken: "access-token"}, f.exchangeErr
}
func (f *fakeProvider) VerifyIDToken(_ context.Context, _, nonce string) (*oidc.VerifiedIDToken, error) {
	if f.verified != nil {
		return f.verified, f.verifyErr
	}
	return &oidc.VerifiedIDToken{
		Subject: "user-1", Email: "user@example.com", Name: "User",
		Username: "user1", Groups: []string{"devs"}, Nonce: nonce,
		Issuer: "https://auth.example.com", Audience: "kubeseal-ui",
		Expiry: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}, f.verifyErr
}
func (f *fakeProvider) RefreshTokens(_ context.Context, _ string) (*oidc.TokenResponse, error) {
	if f.refresh != nil {
		return f.refresh, f.refreshErr
	}
	return &oidc.TokenResponse{IDToken: "id-token", RefreshToken: "refresh-token"}, f.refreshErr
}
func (f *fakeProvider) RevokeToken(_ context.Context, _ string) error { return f.revokeErr }

func testAuthConfig() middleware.AuthConfig {
	return middleware.AuthConfig{
		SessionCookie:      oidc.CookieSession,
		RefreshCookie:      oidc.CookieRefresh,
		CSRFCookie:         oidc.CookieCSRF,
		CookieSecure:       false,
		CookieDomain:       "",
		CSRFTrustedOrigins: []string{"https://app.example.com"},
		SigningKey:         []byte("test-signing-key"),
	}
}

func TestLoginHandlerSetsPKCECookieAndRedirects(t *testing.T) {
	fp := &fakeProvider{}
	auth := NewAuthHandlers(fp, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login", nil)
	auth.LoginHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc == "" || !strings.Contains(loc, "auth.example.com") {
		t.Fatalf("Location = %q, want auth.example.com redirect", loc)
	}
	var pkce *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == oidc.CookiePKCE {
			pkce = c
			break
		}
	}
	if pkce == nil {
		t.Fatal("PKCE cookie not set")
	}
	if !pkce.HttpOnly {
		t.Errorf("PKCE cookie should be HttpOnly")
	}
}

func TestCallbackHandlerEstablishesSession(t *testing.T) {
	fp := &fakeProvider{}
	auth := NewAuthHandlers(fp, testAuthConfig(), []byte("test-signing-key"))
	flow, err := oidc.NewFlowState()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signFlowState(*flow, []byte("test-signing-key"))
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=abc&state="+url.QueryEscape(flow.State), nil)
	req.Header.Set("Cookie", oidc.CookiePKCE+"="+signed)
	auth.CallbackHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302: %s", rr.Code, rr.Body.String())
	}
	var names []string
	for _, c := range rr.Result().Cookies() {
		names = append(names, c.Name)
	}
	for _, want := range []string{oidc.CookieSession, oidc.CookieRefresh, oidc.CookieCSRF} {
		if !contains(names, want) {
			t.Errorf("cookie %s missing; got %v", want, names)
		}
	}
}

func TestCallbackHandlerRejectsStateMismatch(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	flow, _ := oidc.NewFlowState()
	signed, _ := signFlowState(*flow, []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=abc&state=wrong", nil)
	req.Header.Set("Cookie", oidc.CookiePKCE+"="+signed)
	auth.CallbackHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestCallbackHandlerRejectsExpiredFlow(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	stale := &oidc.FlowState{State: "x", Nonce: "n", PKCEVerifier: "v", CreatedAt: time.Now().Add(-10 * time.Minute).Unix()}
	signed, _ := signFlowState(*stale, []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=abc&state=x", nil)
	req.Header.Set("Cookie", oidc.CookiePKCE+"="+signed)
	auth.CallbackHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestCallbackHandlerRejectsBadSignature(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	flow, _ := oidc.NewFlowState()
	badSigned, _ := signFlowState(*flow, []byte("attacker-key"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/callback?code=abc&state="+url.QueryEscape(flow.State), nil)
	req.Header.Set("Cookie", oidc.CookiePKCE+"="+badSigned)
	auth.CallbackHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestMeHandlerRequiresAuthenticatedIdentity(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	auth.MeHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestMeHandlerReturnsIdentity(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := middleware.WithIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil),
		middleware.Identity{Subject: "u1", Email: "u@x", Username: "u1"})
	auth.MeHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"email":"u@x"`) || !strings.Contains(rr.Body.String(), `"username":"u1"`) {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func TestLogoutHandlerClearsCookies(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := middleware.WithIdentity(httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil),
		middleware.Identity{Subject: "u1", CSRF: "csrf-1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Cookie", oidc.CookieCSRF+"=csrf-1")
	auth.LogoutHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	cleared := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge == -1 {
			cleared[c.Name] = true
		}
	}
	for _, want := range []string{oidc.CookieSession, oidc.CookieRefresh, oidc.CookieCSRF} {
		if !cleared[want] {
			t.Errorf("cookie %s not cleared", want)
		}
	}
}

func TestLogoutHandlerRequiresCSRF(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := middleware.WithIdentity(httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil),
		middleware.Identity{Subject: "u1", CSRF: "csrf-1"})
	auth.LogoutHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestCSRFHandlerIssuesTokenWhenUnauthenticated(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil)
	auth.CSRFHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"csrf_token"`) {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func TestCSRFHandlerReturnsSessionToken(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := middleware.WithIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/auth/csrf", nil),
		middleware.Identity{CSRF: "session-csrf"})
	auth.CSRFHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"csrf_token":"session-csrf"`) {
		t.Fatalf("body = %s", rr.Body.String())
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestMeHandlerCarriesGlobalAndScopedGrants pins the shape the UI unions: the flat grant
// list under "capabilities" and the per-namespace grants under "namespaces".
func TestMeHandlerCarriesGlobalAndScopedGrants(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := middleware.WithIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil),
		middleware.Identity{
			Subject:               "u1",
			Email:                 "u@x",
			Capabilities:          []string{"metadata:read"},
			NamespaceCapabilities: map[string][]string{"payments": {"metadata:read", "secret:seal"}},
		})
	auth.MeHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Capabilities []string            `json:"capabilities"`
		Namespaces   map[string][]string `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Capabilities) != 1 || body.Capabilities[0] != "metadata:read" {
		t.Errorf("capabilities = %v", body.Capabilities)
	}
	if got := body.Namespaces["payments"]; len(got) != 2 {
		t.Errorf("namespaces = %v", body.Namespaces)
	}
}

// The key is present even when nothing is scoped, so a client needs no presence check.
func TestMeHandlerAlwaysSendsTheNamespaceMap(t *testing.T) {
	auth := NewAuthHandlers(&fakeProvider{}, testAuthConfig(), []byte("test-signing-key"))
	rr := httptest.NewRecorder()
	req := middleware.WithIdentity(httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil),
		middleware.Identity{Subject: "u1", Capabilities: []string{"metadata:read"}})
	auth.MeHandler(rr, req)
	if !strings.Contains(rr.Body.String(), `"namespaces":{}`) {
		t.Fatalf("body = %s, want an empty namespaces object", rr.Body.String())
	}
}
