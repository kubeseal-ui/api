// Package kubernetes defines the read-only Kubernetes client surface
// the api depends on, plus a deterministic fake for tests.
//
// The api NEVER creates, updates, patches, or deletes Kubernetes
// resources — this package exposes only list/get reads over
// namespaces, SealedSecrets, and (in decrypt-enabled mode) the
// controller's active private-key Secret.
//
// Phase-1 contract (internal-docs/engineering/backend/kubernetes-client.md):
//
//   - Listing is metadata-only; ACL filtering happens at the API layer.
//   - Active-key selection must be deterministic and never depend on
//     API list order: reject malformed entries, pick the newest valid
//     creationTimestamp, use the name as a stable tie-breaker only.
//   - Ambiguous or malformed active-key state fails closed (error),
//     never silently picks the first item.
//   - Key bytes are never cached, logged, or retained after use.
package kubernetes

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Namespace is the minimal metadata projection of a namespace used by
// the api. Only fields the UI needs flow across the boundary.
type Namespace struct {
	Name string
}

// SealedSecret is the minimal metadata projection of a SealedSecret.
// Ciphertext and other spec internals are deliberately NOT exposed
// here — the api returns YAML on demand through the crypto layer.
type SealedSecret struct {
	Name      string
	Namespace string
	// Scope is the sealed secret's mobility scope (strict,
	// namespace-wide, cluster-wide). Derived from annotations.
	Scope string
}

// ActiveKey is the resolved controller private key. Callers must
// release Key after use (zero it); the client never retains it.
type ActiveKey struct {
	// Name of the Secret the key came from (for audit logging).
	Name string
	// Key is the parsed RSA private key material. Bytes are copied
	// out of the k8s Secret on demand and zeroed after use by the
	// caller.
	Key []byte
}

// Client is the read-only Kubernetes surface. Implementations must be
// safe for concurrent use.
type Client interface {
	// ListNamespaces returns all namespaces the service account can
	// see. ACL filtering is the caller's responsibility.
	ListNamespaces(ctx context.Context) ([]Namespace, error)

	// GetSealedSecret returns one SealedSecret by namespace/name.
	GetSealedSecret(ctx context.Context, namespace, name string) (SealedSecret, error)

	// ListSealedSecrets returns all SealedSecrets in a namespace.
	ListSealedSecrets(ctx context.Context, namespace string) ([]SealedSecret, error)

	// FindActiveControllerKey returns the controller's active private
	// key. Only used in decrypt-enabled mode. Fails closed on
	// ambiguous or malformed state (see package doc).
	FindActiveControllerKey(ctx context.Context) (ActiveKey, error)
}

// Secret is an alias so tests can construct fake controller key
// Secrets without importing corev1 everywhere.
type Secret = corev1.Secret

// ObjectMeta alias for constructing test fixtures.
type ObjectMeta = metav1.ObjectMeta
