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

func NewFake(namespaces []Namespace, secrets []SealedSecret, keys []Secret) *Fake {
	return &Fake{namespaces: namespaces, secrets: secrets, keys: keys}
}

func (f *Fake) ListNamespaces(_ context.Context) ([]Namespace, error) {
	out := make([]Namespace, len(f.namespaces))
	copy(out, f.namespaces)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

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

func (f *Fake) GetSealedSecret(_ context.Context, namespace, name string) (SealedSecret, error) {
	for _, s := range f.secrets {
		if s.Namespace == namespace && s.Name == name {
			return s, nil
		}
	}
	return SealedSecret{}, ErrNotFound
}

var ErrNotFound = errors.New("kubernetes: not found")

// FindActiveControllerKey applies pickActive's rule to the fixture keys, failing closed
// when none is valid.
func (f *Fake) FindActiveControllerKey(_ context.Context) (ActiveKey, error) {
	valid := f.validKeys()
	if len(valid) == 0 {
		return ActiveKey{}, fmt.Errorf("kubernetes: no valid active key found")
	}
	return pickActive(valid)
}

func (f *Fake) FindAllControllerKeys(_ context.Context) ([]ActiveKey, error) {
	valid := f.validKeys()
	if len(valid) == 0 {
		return nil, fmt.Errorf("kubernetes: no valid active key found")
	}
	out := make([]ActiveKey, len(valid))
	for i, item := range valid {
		out[i] = ActiveKey{Name: item.Name, Key: append([]byte(nil), item.Data["tls.key"]...)}
	}
	return out, nil
}

// validKeys keeps only the fixture Secrets carrying both tls.crt and tls.key.
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

// pickActive picks the newest creationTimestamp, using the name as the stable
// tie-breaker. Keys tying on both are indistinguishable (ambiguous) and fail closed.
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
