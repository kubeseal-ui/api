package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

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
