// Package kubernetes defines the read-only Kubernetes client surface the api depends on,
// plus a deterministic fake for tests.
//
// The api never writes to Kubernetes: only list/get reads over namespaces, SealedSecrets,
// and (in decrypt-enabled mode) the controller's private-key Secret. Active-key selection
// is deterministic and never depends on API list order; ambiguous or malformed state fails
// closed rather than picking the first item. Key bytes are never cached, logged, or
// retained after use.
package kubernetes

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Namespace is the metadata projection of a namespace the api exposes to the UI.
type Namespace struct {
	Name          string `json:"name"`
	GitManaged    bool   `json:"git_managed"`
	DeliveryMode  string `json:"delivery_mode,omitempty"`
	GitRepository string `json:"git_mapping,omitempty"`
	// Capabilities is the caller's effective capability set in this namespace, filled in by
	// the handler from the authenticated identity — never by the client, which knows
	// nothing about callers.
	Capabilities []string `json:"capabilities"`
}

type DriftStatus string

const (
	DriftSync     DriftStatus = "in-sync"
	DriftDiverged DriftStatus = "diverged"
	DriftUnknown  DriftStatus = "unknown"
)

// SealedSecret is the metadata projection of a SealedSecret. Ciphertext and other spec
// internals stay out of it; YAML is served on demand through the crypto layer.
type SealedSecret struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// Scope is the sealed secret's mobility scope (strict, namespace-wide, cluster-wide),
	// derived from annotations.
	Scope     string   `json:"scope"`
	KeyCount  int      `json:"key_count"`
	Keys      []string `json:"keys,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	YAML      string   `json:"-"`
}

// ActiveKey is the resolved controller private key; the client never retains it, and
// callers must zero Key after use.
type ActiveKey struct {
	// Name of the Secret the key came from, for audit logging.
	Name string
	// Key is the parsed RSA private key material, copied out of the Secret on demand and
	// zeroed after use by the caller.
	Key []byte
}

// Client is the read-only Kubernetes surface. Implementations must be safe for concurrent
// use.
type Client interface {
	// ListNamespaces returns all namespaces the service account can see; ACL filtering is
	// the caller's responsibility.
	ListNamespaces(ctx context.Context) ([]Namespace, error)

	GetSealedSecret(ctx context.Context, namespace, name string) (SealedSecret, error)

	ListSealedSecrets(ctx context.Context, namespace string) ([]SealedSecret, error)

	// FindActiveControllerKey returns the controller's active private key (decrypt-enabled
	// mode only, see the package doc on failing closed).
	FindActiveControllerKey(ctx context.Context) (ActiveKey, error)

	// FindAllControllerKeys returns every valid controller private key, so secrets sealed
	// under previously rotated keys can still be unsealed.
	FindAllControllerKeys(ctx context.Context) ([]ActiveKey, error)
}

// Secret and ObjectMeta are aliases so tests can build fixtures without importing corev1.
type Secret = corev1.Secret

type ObjectMeta = metav1.ObjectMeta
