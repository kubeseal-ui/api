package oidc

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// discoveryTimeout bounds one lazy discovery attempt, matching the boot-time budget it replaced.
const discoveryTimeout = 10 * time.Second

// LazyProvider defers OIDC discovery until first use and retries on every later call until it
// succeeds, so an API that boots before its issuer can recover without a restart. Fail-closed is
// preserved: until discovery succeeds every method returns an error, and the login flow never
// mints a session.
type LazyProvider struct {
	cfg Config

	mu    sync.Mutex
	inner *Provider
}

func NewLazyProvider(cfg Config) *LazyProvider {
	return &LazyProvider{cfg: cfg}
}

// load returns the discovered provider, attempting discovery once per call while it is still down.
func (p *LazyProvider) load(ctx context.Context) (*Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inner != nil {
		return p.inner, nil
	}
	provider, err := NewProvider(ctx, p.cfg)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider discovery: %w", err)
	}
	p.inner = provider
	return p.inner, nil
}

// loadFresh discovers with a fresh timeout budget, for methods that carry no caller context.
func (p *LazyProvider) loadFresh() (*Provider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	return p.load(ctx)
}

func (p *LazyProvider) LoginURL(flow *FlowState) (string, error) {
	provider, err := p.loadFresh()
	if err != nil {
		return "", err
	}
	return provider.LoginURL(flow)
}

func (p *LazyProvider) ExchangeCode(ctx context.Context, code, pkceVerifier string) (*TokenResponse, error) {
	provider, err := p.load(ctx)
	if err != nil {
		return nil, err
	}
	return provider.ExchangeCode(ctx, code, pkceVerifier)
}

func (p *LazyProvider) VerifyIDToken(ctx context.Context, idToken, nonce string) (*VerifiedIDToken, error) {
	provider, err := p.load(ctx)
	if err != nil {
		return nil, err
	}
	return provider.VerifyIDToken(ctx, idToken, nonce)
}

func (p *LazyProvider) RefreshTokens(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	provider, err := p.load(ctx)
	if err != nil {
		return nil, err
	}
	return provider.RefreshTokens(ctx, refreshToken)
}

func (p *LazyProvider) RevokeToken(ctx context.Context, token string) error {
	provider, err := p.load(ctx)
	if err != nil {
		return err
	}
	return provider.RevokeToken(ctx, token)
}
