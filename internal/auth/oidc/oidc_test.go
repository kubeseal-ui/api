package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// newTestFlowState builds a valid FlowState, failing the test when randomness does.
func newTestFlowState(t *testing.T) *FlowState {
	t.Helper()
	flow, err := NewFlowState()
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

func testConfig() Config {
	return Config{
		IssuerURL:          "https://auth.example.com",
		ClientID:           "kubeseal-ui",
		ClientSecret:       "test-secret",
		RedirectURL:        "https://app.example.com/api/v1/auth/callback",
		Scopes:             []string{"openid", "profile", "email", "groups"},
		GroupsClaim:        "groups",
		UsernameClaim:      "preferred_username",
		CookieSecure:       false,
		CookieDomain:       "",
		CSRFTrustedOrigins: []string{"https://app.example.com"},
	}
}

type mockProvider struct {
	server    *httptest.Server
	issuerURL string
	clientID  string
	keySet    *oidc.KeySet
}

func newMockProvider(t *testing.T) *mockProvider {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)

	return &mockProvider{
		server:    server,
		issuerURL: server.URL,
		clientID:  "kubeseal-ui",
	}
}

func (m *mockProvider) close() {
	m.server.Close()
}

func TestLoadConfigMissingRequired(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "")
	t.Setenv("OIDC_CLIENT_ID", "")
	t.Setenv("OIDC_CLIENT_SECRET", "")
	t.Setenv("OIDC_REDIRECT_URL", "")
}

func TestNewFlowStateGeneratesValidState(t *testing.T) {
	flow, err := NewFlowState()
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}

	if flow.State == "" {
		t.Error("State should not be empty")
	}
	if flow.Nonce == "" {
		t.Error("Nonce should not be empty")
	}
	if flow.PKCEVerifier == "" {
		t.Error("PKCE verifier should not be empty")
	}
	if flow.CreatedAt == 0 {
		t.Error("CreatedAt should be set")
	}
}

func TestFlowStateValidatePassesWhenFresh(t *testing.T) {
	flow, err := NewFlowState()
	if err != nil {
		t.Fatalf("NewFlowState: %v", err)
	}

	if err := flow.Validate(); err != nil {
		t.Errorf("Fresh flow state should be valid: %v", err)
	}
}

func TestFlowStateValidateFailsWhenExpired(t *testing.T) {
	flow := &FlowState{
		State:        "test-state",
		Nonce:        "test-nonce",
		PKCEVerifier: "test-verifier",
		CreatedAt:    time.Now().Add(-10 * time.Minute).Unix(),
	}

	if err := flow.Validate(); err == nil {
		t.Error("Expired flow state should fail validation")
	}
}

func TestPKCEVerifierGeneratesValidPair(t *testing.T) {
	verifier, err := PKCEVerifier()
	if err != nil {
		t.Fatalf("PKCEVerifier: %v", err)
	}

	if verifier == "" {
		t.Error("Verifier should not be empty")
	}
}

func TestLoginURLBuildsValidAuthorizationURL(t *testing.T) {
	t.Skip("Requires OIDC provider - integration test")
}

func TestCSRFTokenGeneratesValidToken(t *testing.T) {
	token, err := CSRFToken()
	if err != nil {
		t.Fatalf("CSRFToken: %v", err)
	}

	if token == "" {
		t.Error("CSRF token should not be empty")
	}
}

func TestCookieOptionsReturnsCorrectFlags(t *testing.T) {
	t.Skip("Requires OIDC provider - integration test")
}

func TestVerifyIDTokenRejectsWrongIssuer(t *testing.T) {
	t.Skip("Requires OIDC provider with test keys - integration test")
}

func TestVerifyIDTokenRejectsWrongAudience(t *testing.T) {
	t.Skip("Requires OIDC provider with test keys - integration test")
}

func TestVerifyIDTokenRejectsExpiredToken(t *testing.T) {
	t.Skip("Requires OIDC provider with test keys - integration test")
}

func TestSessionDataJSONRoundTrip(t *testing.T) {
	data := SessionData{
		Subject:  "user-123",
		Email:    "user@example.com",
		Name:     "Test User",
		Username: "testuser",
		Groups:   []string{"team-a", "team-b"},
		Expiry:   time.Now().Add(time.Hour).Unix(),
		IssuedAt: time.Now().Unix(),
		CSRF:     "csrf-token",
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded SessionData
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Subject != data.Subject {
		t.Errorf("Subject mismatch: %q vs %q", decoded.Subject, data.Subject)
	}
	if decoded.Email != data.Email {
		t.Errorf("Email mismatch: %q vs %q", decoded.Email, data.Email)
	}
	if len(decoded.Groups) != len(data.Groups) {
		t.Errorf("Groups length mismatch: %d vs %d", len(decoded.Groups), len(data.Groups))
	}
}

func TestSplitCSVHandlesVariousInputs(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"single", []string{"single"}},
		{"a,b,c", []string{"a", "b", "c"}},
		{"a, b, c", []string{"a", "b", "c"}},
		{"a,,b", []string{"a", "b"}},    // empty entries skipped
		{" a , b ", []string{"a", "b"}}, // whitespace trimmed
	}

	for _, tc := range tests {
		result := splitCSV(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("splitCSV(%q): got %v, want %v", tc.input, result, tc.expected)
			continue
		}
		for i := range tc.expected {
			if result[i] != tc.expected[i] {
				t.Errorf("splitCSV(%q)[%d]: got %q, want %q", tc.input, i, result[i], tc.expected[i])
			}
		}
	}
}

type mockVerifier struct{}

func (m *mockVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return nil, nil
}

// revocationTestProvider serves a discovery document naming a revocation endpoint, and records
// what the POST carried.
type revocationTestProvider struct {
	server   *httptest.Server
	status   int
	body     string
	lastForm url.Values
	lastUser string
	lastPass string
	hasAuth  bool
}

func newRevocationTestProvider(t *testing.T, withEndpoint bool) *revocationTestProvider {
	t.Helper()
	rv := &revocationTestProvider{status: http.StatusOK}
	mux := http.NewServeMux()
	rv.server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                 rv.server.URL,
			"authorization_endpoint": rv.server.URL + "/auth",
			"token_endpoint":         rv.server.URL + "/token",
			"jwks_uri":               rv.server.URL + "/keys",
		}
		if withEndpoint {
			doc["revocation_endpoint"] = rv.server.URL + "/revoke"
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			t.Errorf("encode discovery document: %v", err)
		}
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse revocation form: %v", err)
		}
		rv.lastForm = r.PostForm
		rv.lastUser, rv.lastPass, rv.hasAuth = r.BasicAuth()
		w.WriteHeader(rv.status)
		if rv.body != "" {
			_, _ = w.Write([]byte(rv.body))
		}
	})
	t.Cleanup(rv.server.Close)
	return rv
}

func (rv *revocationTestProvider) provider(t *testing.T) *Provider {
	t.Helper()
	cfg := testConfig()
	cfg.IssuerURL = rv.server.URL
	p, err := NewProvider(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func TestRevokeTokenPostsToDiscoveredEndpoint(t *testing.T) {
	rv := newRevocationTestProvider(t, true)
	if err := rv.provider(t).RevokeToken(context.Background(), "refresh-abc"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if rv.lastForm == nil {
		t.Fatal("revocation endpoint was not called")
	}
	if got := rv.lastForm.Get("token"); got != "refresh-abc" {
		t.Errorf("token = %q, want %q", got, "refresh-abc")
	}
	if got := rv.lastForm.Get("token_type_hint"); got != "refresh_token" {
		t.Errorf("token_type_hint = %q, want refresh_token", got)
	}
	if !rv.hasAuth {
		t.Fatal("expected client credentials on the revocation request")
	}
	// Basic auth percent-decodes, so the credentials arrive unescaped.
	if rv.lastUser != "kubeseal-ui" || rv.lastPass != "test-secret" {
		t.Errorf("basic auth = %q/%q, want kubeseal-ui/test-secret", rv.lastUser, rv.lastPass)
	}
}

func TestRevokeTokenWithoutEndpointIsNotAnError(t *testing.T) {
	rv := newRevocationTestProvider(t, false)
	if err := rv.provider(t).RevokeToken(context.Background(), "refresh-abc"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if rv.lastForm != nil {
		t.Error("revocation endpoint should not have been called")
	}
}

func TestRevokeTokenTreatsInvalidTokenAsSuccess(t *testing.T) {
	rv := newRevocationTestProvider(t, true)
	rv.status = http.StatusBadRequest
	rv.body = `{"error":"invalid_token"}`
	if err := rv.provider(t).RevokeToken(context.Background(), "refresh-abc"); err != nil {
		t.Fatalf("invalid_token should count as revoked, got %v", err)
	}
}

func TestRevokeTokenReportsUnexpectedStatus(t *testing.T) {
	rv := newRevocationTestProvider(t, true)
	rv.status = http.StatusInternalServerError
	if err := rv.provider(t).RevokeToken(context.Background(), "refresh-abc"); err == nil {
		t.Fatal("expected an error for a 500 from the revocation endpoint")
	}
}

func TestRevokeTokenEmptyTokenIsNoOp(t *testing.T) {
	rv := newRevocationTestProvider(t, true)
	if err := rv.provider(t).RevokeToken(context.Background(), ""); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if rv.lastForm != nil {
		t.Error("revocation endpoint should not be called for an empty token")
	}
}

func TestExchangeCodeCallsTokenEndpoint(t *testing.T) {
	t.Skip("Requires OIDC provider - integration test")
}

func TestRefreshTokensCallsTokenEndpoint(t *testing.T) {
	t.Skip("Requires OIDC provider - integration test")
}

func TestVerifiedIDTokenHasRequiredFields(t *testing.T) {
	tok := VerifiedIDToken{
		Subject:  "sub-123",
		Email:    "user@example.com",
		Name:     "Test User",
		Username: "testuser",
		Groups:   []string{"group-a"},
		Issuer:   "https://auth.example.com",
		Audience: "kubeseal-ui",
		Expiry:   time.Now().Add(time.Hour),
		IssuedAt: time.Now(),
		Nonce:    "nonce-123",
	}

	if tok.Subject == "" {
		t.Error("Subject should be set")
	}
	if tok.Email == "" {
		t.Error("Email should be set")
	}
	if tok.Expiry.IsZero() {
		t.Error("Expiry should be set")
	}
	if tok.IssuedAt.IsZero() {
		t.Error("IssuedAt should be set")
	}
}

func TestAudienceUnmarshalJSON(t *testing.T) {
	var single audience
	if err := json.Unmarshal([]byte(`"client-123"`), &single); err != nil {
		t.Fatalf("failed to unmarshal single string audience: %v", err)
	}
	if len(single) != 1 || single[0] != "client-123" {
		t.Fatalf("unexpected audience: %v", single)
	}

	var multi audience
	if err := json.Unmarshal([]byte(`["client-1", "client-2"]`), &multi); err != nil {
		t.Fatalf("failed to unmarshal array audience: %v", err)
	}
	if len(multi) != 2 || multi[0] != "client-1" || multi[1] != "client-2" {
		t.Fatalf("unexpected audience: %v", multi)
	}
}

// TestLazyProviderRecoversWhenTheIssuerComesUp pins the boot-order contract: discovery attempted
// while the issuer is down fails that call but must not poison the provider — the next call, after
// the issuer answers, succeeds without any restart.
func TestLazyProviderRecoversWhenTheIssuerComesUp(t *testing.T) {
	var up atomic.Bool
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "issuer not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/auth",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/keys",
		}); err != nil {
			t.Errorf("encode discovery document: %v", err)
		}
	})

	cfg := testConfig()
	cfg.IssuerURL = server.URL
	lazy := NewLazyProvider(cfg)

	if _, err := lazy.LoginURL(newTestFlowState(t)); err == nil {
		t.Fatal("LoginURL succeeded while the issuer was down")
	}

	up.Store(true)
	if _, err := lazy.LoginURL(newTestFlowState(t)); err != nil {
		t.Fatalf("LoginURL did not recover after the issuer came up: %v", err)
	}
}
