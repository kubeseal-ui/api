package oidc

import (
	"context"
)

// AuthProvider is the contract the auth HTTP handlers depend on: *Provider implements it,
// and tests substitute a fake.
type AuthProvider interface {
	LoginURL(flow *FlowState) (string, error)
	ExchangeCode(ctx context.Context, code, pkceVerifier string) (*TokenResponse, error)
	VerifyIDToken(ctx context.Context, idToken, nonce string) (*VerifiedIDToken, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error)
	RevokeToken(ctx context.Context, token string) error
}
