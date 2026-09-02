package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Fake is a deterministic in-memory Client for unit tests.
type Fake struct {
	namespaces []Namespace
	secrets    []SealedSecret
	keys       []Secret
}

// NewFake builds a Fake with the given fixtures.
func NewFake(namespaces []Namespace, secrets []SealedSecret, keys []Secret) *Fake {
	return &Fake{namespaces: namespaces, secrets: secrets, keys: keys}
}

// ListNamespaces returns a sorted copy of the fixture namespaces.
func (f *Fake) ListNamespaces(_ context.Context) ([]Namespace, error) {
	out := make([]Namespace, len(f.namespaces))
	copy(out, f.namespaces)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListSealedSecrets returns a sorted copy of the fixture secrets
// filtered to one namespace.
func (f *Fake) ListSealedSecrets(_ context.Context, namespace string) ([]SealedSecret, error) {
	var out []SealedSecret
	for _, s := range f.secrets {
		if s.Namespace == namespace {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetSealedSecret returns one fixture secret or ErrNotFound.
func (f *Fake) GetSealedSecret(_ context.Context, namespace, name string) (SealedSecret, error) {
	for _, s := range f.secrets {
		if s.Namespace == namespace && s.Name == name {
			return s, nil
		}
	}
	return SealedSecret{}, ErrNotFound
}

// ErrNotFound is returned when a requested resource is absent.
var ErrNotFound = errors.New("kubernetes: not found")

// FindActiveControllerKey selects the active key deterministically:
// valid entries only (tls.crt + tls.key), newest creationTimestamp
// wins, name is the tie-breaker. Ambiguous or malformed state fails
// closed. See kubernetes-client.md for the contract.
func (f *Fake) FindActiveControllerKey(_ context.Context) (ActiveKey, error) {
	valid := f.validKeys()
	if len(valid) == 0 {
		return ActiveKey{}, fmt.Errorf("kubernetes: no valid active key found")
	}
	return pickActive(valid)
}

// validKeys filters fixture Secrets to those with tls.crt and tls.key.
func (f *Fake) validKeys() []Secret {
	var out []Secret
	for _, k := range f.keys {
		if _, ok := k.Data["tls.crt"]; !ok {
			continue
		}
		if _, ok := k.Data["tls.key"]; !ok {
			continue
		}
		out = append(out, k)
	}
	return out
}

// pickActive implements the selection rule over pre-validated keys:
// newest creationTimestamp wins, name is the stable tie-breaker.
// Two keys that tie on BOTH timestamp and name are indistinguishable
// (ambiguous) and fail closed. See kubernetes-client.md.
func pickActive(keys []Secret) (ActiveKey, error) {
	if len(keys) == 0 {
		return ActiveKey{}, fmt.Errorf("kubernetes: no valid active key found")
	}
	best := keys[0]
	ambiguous := false
	for _, k := range keys[1:] {
		if k.CreationTimestamp.After(best.CreationTimestamp.Time) {
			best = k
			ambiguous = false
			continue
		}
		if k.CreationTimestamp.Equal(&best.CreationTimestamp) {
			if k.Name == best.Name {
				ambiguous = true
				continue
			}
			if strings.Compare(k.Name, best.Name) < 0 {
				best = k
			}
		}
	}
	if ambiguous {
		return ActiveKey{}, fmt.Errorf("kubernetes: ambiguous active key state (duplicate name %q)", best.Name)
	}
	return ActiveKey{
		Name: best.Name,
		Key:  append([]byte(nil), best.Data["tls.key"]...),
	}, nil
}
