package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/kubeseal-ui/api/internal/kubernetes"
)

type kubePrivateKeyProvider struct{ client kubernetes.Client }

// PrivateKeys returns every controller key the cluster still holds, not
// just the active one. The sealed-secrets controller rotates its sealing
// key on a schedule and retains the old keys so it can still decrypt
// previously sealed secrets; decryption here has the same requirement.
func (p kubePrivateKeyProvider) PrivateKeys(ctx context.Context) ([]*rsa.PrivateKey, error) {
	keys, err := p.client.FindAllControllerKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*rsa.PrivateKey, 0, len(keys))
	for _, key := range keys {
		parsed, err := parseRSAPrivateKeyPEM(key.Key)
		if err != nil {
			// One unreadable key must not disable decryption for the
			// secrets the remaining keys can still open.
			slog.Warn("skipping unreadable controller key", "key", key.Name, "error", err)
			continue
		}
		out = append(out, parsed)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable controller key among %d labelled secrets", len(keys))
	}
	return out, nil
}

func parseRSAPrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("controller key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse controller key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("controller key is not RSA")
	}
	return key, nil
}
