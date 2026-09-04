// Package oidc: AuthProvider is the contract the auth HTTP handlers depend on.
// The production *Provider satisfies it; tests can substitute a fake.
package oidc

import (
	"context"
	"net/http"
)

// AuthProvider is the handler-facing contract. *Provider implements it.
type AuthProvider interface {
	LoginURL(flow *FlowState) (string, error)
	ExchangeCode(ctx context.Context, code, pkceVerifier string) (*TokenResponse, error)
	VerifyIDToken(ctx context.Context, idToken, nonce string) (*VerifiedIDToken, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error)
	RevokeToken(ctx context.Context, token string) error
	CookieOptions(path string, maxAge int) *http.Cookie
}
