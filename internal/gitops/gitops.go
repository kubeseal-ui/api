// Package gitops defines the delivery-provider interface the api uses
// to persist sealed YAML to the configuration store.
//
// Phase-1 contract: interface only. NO implementation ships in Phase 1
// — delivery lands in Phase 4 per internal-docs/implementation/phase-1.md
// ("Git delivery is delivered in later phases"). This package exists so
// handlers can depend on the interface today and Phase 4 can supply a
// concrete provider without changing call sites.
package gitops

import "context"

// Provider persists a sealed resource to the configuration store and
// returns the canonical location it was written to. Implementations
// must attribute the change to the authenticated user (the API passes
// the identity through), never to a shared bot identity.
type Provider interface {
	// Save writes the sealed YAML for the given namespace/name and
	// returns a human-readable location (path or URL) suitable for
	// the UI to display.
	Save(ctx context.Context, namespace, name, sealedYAML string) (string, error)
}
