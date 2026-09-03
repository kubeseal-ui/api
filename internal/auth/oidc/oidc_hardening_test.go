package oidc

import (
	"net/http"
	"testing"
)

func TestExtractConfiguredClaims(t *testing.T) {
	claims := map[string]any{"sub": "u", "email": "u@example.test", "login": "alice", "roles": []any{"admin", "ops"}}
	got, err := extractConfiguredClaims(claims, "roles", "login")
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" || len(got.Groups) != 2 || got.Groups[1] != "ops" {
		t.Fatalf("unexpected claims: %#v", got)
	}
}

func TestExtractConfiguredClaimsRejectsMissingRequiredUsername(t *testing.T) {
	_, err := extractConfiguredClaims(map[string]any{"sub": "u", "email": "u@example.test", "roles": []any{"admin"}}, "roles", "login")
	if err == nil {
		t.Fatal("expected missing configured username to fail")
	}
}

func TestCookieOptionsContract(t *testing.T) {
	p := &Provider{cfg: Config{CookieSecure: true, CookieDomain: "app.example.test"}}
	c := p.CookieOptions("/api/v1", 60)
	if c.Path != "/api/v1" || c.MaxAge != 60 || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Domain != "app.example.test" {
		t.Fatalf("cookie contract violated: %#v", c)
	}
}

func TestRefreshTokensRejectsEmptyRefreshToken(t *testing.T) {
	p := &Provider{}
	if _, err := p.RefreshTokens(nil, ""); err == nil {
		t.Fatal("expected empty refresh token to fail")
	}
}
