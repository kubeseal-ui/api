package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/kubeseal-ui/api/internal/kubernetes"
)

type kubePrivateKeyProvider struct{ client kubernetes.Client }

func (p kubePrivateKeyProvider) PrivateKey(ctx context.Context) (*rsa.PrivateKey, error) {
	active, err := p.client.FindActiveControllerKey(ctx)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(active.Key)
	if block == nil {
		return nil, fmt.Errorf("active controller key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse active controller key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("active controller key is not RSA")
	}
	return key, nil
}
