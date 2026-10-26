// Package crypto seals and unseals SealedSecrets in-process, never via the kubeseal binary.
package crypto

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami/sealed-secrets/pkg/crypto"
	"github.com/bitnami/sealed-secrets/pkg/kubeseal"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

// Scope is how tightly a sealed secret is pinned to a namespace/name.
type Scope int

const (
	StrictScope        Scope = Scope(ssv1alpha1.StrictScope)
	NamespaceWideScope Scope = Scope(ssv1alpha1.NamespaceWideScope)
	ClusterWideScope   Scope = Scope(ssv1alpha1.ClusterWideScope)
)

func (s Scope) String() string {
	switch s {
	case StrictScope:
		return "strict"
	case NamespaceWideScope:
		return "namespace-wide"
	case ClusterWideScope:
		return "cluster-wide"
	default:
		return "unknown"
	}
}

// Set parses a scope string; Set and Type implement flag.Value.
func (s *Scope) Set(v string) error {
	switch strings.ToLower(v) {
	case "strict":
		*s = StrictScope
	case "namespace-wide":
		*s = NamespaceWideScope
	case "cluster-wide":
		*s = ClusterWideScope
	default:
		return fmt.Errorf("invalid scope %q: must be strict, namespace-wide, or cluster-wide", v)
	}
	return nil
}

func (s *Scope) Type() string { return "scope" }

func (s Scope) SealingScope() ssv1alpha1.SealingScope {
	return ssv1alpha1.SealingScope(s)
}

type Provider interface {
	Get(ctx context.Context) (*x509.Certificate, error)
}

// PrivateKeyProvider must return every key the controller holds, including pre-rotation ones.
type PrivateKeyProvider interface {
	PrivateKeys(ctx context.Context) ([]*rsa.PrivateKey, error)
}

// KeyCacheInvalidator lets DecryptYAML drop a cached key list and retry before failing.
type KeyCacheInvalidator interface {
	InvalidateKeyCache()
}

// Wrapper seals, unseals, and reseals; all methods are concurrency-safe.
type Wrapper struct {
	cert   Provider
	priv   PrivateKeyProvider
	codecs serializer.CodecFactory
}

// New builds a Wrapper from the given providers; priv may be nil to disable decryption.
func New(cert Provider, priv PrivateKeyProvider) *Wrapper {
	codecs := serializer.NewCodecFactory(scheme.Scheme)
	return &Wrapper{
		cert:   cert,
		priv:   priv,
		codecs: codecs,
	}
}

// EncryptYAML seals Secret YAML; scope pins how tightly the result binds to namespace/name.
func (w *Wrapper) EncryptYAML(ctx context.Context, secretYAML string, namespace, name string, scope Scope) (string, error) {
	pubCert, err := w.cert.Get(ctx)
	if err != nil {
		return "", fmt.Errorf("crypto: fetch cert: %w", err)
	}

	pubKey, ok := pubCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("crypto: cert public key is not RSA (got %T)", pubCert.PublicKey)
	}

	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(secretYAML), 4096)
	var secret corev1.Secret
	if decodeErr := decoder.Decode(&secret); decodeErr != nil {
		return "", fmt.Errorf("crypto: decode secret YAML: %w", decodeErr)
	}

	// Scope annotations must be set before sealing, or unseal hits a label mismatch.
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	ssv1alpha1.UpdateScopeAnnotations(secret.Annotations, scope.SealingScope())

	sealed, err := ssv1alpha1.NewSealedSecret(w.codecs, pubKey, &secret)
	if err != nil {
		return "", fmt.Errorf("crypto: seal secret: %w", err)
	}

	ssv1alpha1.UpdateScopeAnnotations(sealed.Annotations, scope.SealingScope())

	if name != "" {
		sealed.Name = name
		sealed.Spec.Template.Name = name
	}
	if namespace != "" {
		sealed.Namespace = namespace
		sealed.Spec.Template.Namespace = namespace
	}

	return encodeSealedSecret(sealed, w.codecs)
}

// encodeSealedSecret renders a SealedSecret as YAML. The codec emits one-line JSON; converting it
// keeps Git diffs readable.
func encodeSealedSecret(sealed *ssv1alpha1.SealedSecret, codecs serializer.CodecFactory) (string, error) {
	var buf bytes.Buffer
	if err := codecs.LegacyCodec(ssv1alpha1.SchemeGroupVersion).Encode(sealed, &buf); err != nil {
		return "", fmt.Errorf("crypto: encode sealed secret: %w", err)
	}
	y, err := sigsyaml.JSONToYAML(buf.Bytes())
	if err != nil {
		return "", fmt.Errorf("crypto: encode sealed secret: %w", err)
	}
	return string(y), nil
}

// DecryptYAML unseals a SealedSecret back to Secret YAML. It requires the private-key
// provider.
func (w *Wrapper) DecryptYAML(ctx context.Context, sealedYAML string) (string, error) {
	if w.priv == nil {
		return "", fmt.Errorf("crypto: decrypt is disabled (ENABLE_DECRYPT=false)")
	}

	secret, err := w.unseal(ctx, sealedYAML)
	if err != nil {
		// No key opened it: drop a cached key list, if the provider keeps one, and retry once.
		if stale, ok := w.priv.(KeyCacheInvalidator); ok {
			stale.InvalidateKeyCache()
			if retried, retryErr := w.unseal(ctx, sealedYAML); retryErr == nil {
				secret, err = retried, nil
			}
		}
	}
	if err != nil {
		return "", err
	}

	// Render as stringData to match the kubeseal CLI's unseal output.
	sd := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		sd[k] = string(v)
	}
	secret.StringData = sd
	secret.Data = nil

	y, err := sigsyaml.Marshal(secret)
	if err != nil {
		return "", fmt.Errorf("crypto: encode secret: %w", err)
	}
	return string(y), nil
}

// unseal fetches the controller keys and opens the document with them.
func (w *Wrapper) unseal(ctx context.Context, sealedYAML string) (*corev1.Secret, error) {
	privKeys, err := w.privateKeyMap(ctx)
	if err != nil {
		return nil, err
	}

	sealed, err := parseSealedSecret(sealedYAML)
	if err != nil {
		return nil, err
	}

	// UnsealWithoutTemplate: spec.template.data is unauthenticated and must never dictate revealed values.
	secret, err := sealed.UnsealWithoutTemplate(w.codecs, privKeys)
	if err != nil {
		return nil, fmt.Errorf("crypto: unseal: %w", err)
	}
	return secret, nil
}

// privateKeyMap indexes keys by fingerprint so pre-rotation secrets still unseal.
func (w *Wrapper) privateKeyMap(ctx context.Context) (map[string]*rsa.PrivateKey, error) {
	keys, err := w.priv.PrivateKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("crypto: fetch private keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("crypto: no controller private keys available")
	}
	out := make(map[string]*rsa.PrivateKey, len(keys))
	for _, key := range keys {
		fp, err := crypto.PublicKeyFingerprint(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("crypto: fingerprint key: %w", err)
		}
		out[fp] = key
	}
	return out, nil
}

// Mutation is one entry change in a reseal batch.
type Mutation struct {
	Key   string
	Value string
	Op    ResealOp
}

// ResealOp is a mutation operation for Reseal and ResealMany.
type ResealOp string

const (
	ResealReplace ResealOp = "replace"
	ResealAdd     ResealOp = "add"
	ResealDelete  ResealOp = "delete"
)

// ErrInvalidMutation marks a caller error, so handlers answer 4xx instead of 500.
var ErrInvalidMutation = errors.New("crypto: invalid mutation")

// ResealMany decrypts once, applies the whole batch, and re-encrypts once; nothing applies unless every entry validates.
func (w *Wrapper) ResealMany(ctx context.Context, sealedYAML string, mutations []Mutation) (string, error) {
	if w.priv == nil {
		return "", fmt.Errorf("crypto: decrypt is disabled (ENABLE_DECRYPT=false)")
	}
	if len(mutations) == 0 {
		return "", fmt.Errorf("%w: no mutations given", ErrInvalidMutation)
	}

	// spec.template.data would be silently dropped by a reseal, so refuse documents that carry it.
	sealed, err := parseSealedSecret(sealedYAML)
	if err != nil {
		return "", err
	}
	if len(sealed.Spec.Template.Data) > 0 {
		return "", fmt.Errorf("%w: spec.template.data is not carried across a reseal", ErrInvalidMutation)
	}

	secretYAML, err := w.DecryptYAML(ctx, sealedYAML)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt for reseal: %w", err)
	}

	updated, scope, err := mutateSecretYAML(secretYAML, mutations, w.codecs)
	if err != nil {
		return "", err
	}

	// Re-seal at the Secret's existing scope, never a default.
	return w.EncryptYAML(ctx, updated, "", "", scope)
}

// Reseal routes a single mutation through ResealMany.
func (w *Wrapper) Reseal(ctx context.Context, sealedYAML, key, newValue string, op ResealOp) (string, error) {
	return w.ResealMany(ctx, sealedYAML, []Mutation{{Key: key, Value: newValue, Op: op}})
}

// SealMutations applies a batch to a SealedSecret without decrypting anything: add and replace
// seal only the value they introduce, delete drops one entry, and every other entry is carried
// through untouched. Only the controller's public certificate is needed.
func (w *Wrapper) SealMutations(ctx context.Context, sealedYAML string, mutations []Mutation) (string, error) {
	if len(mutations) == 0 {
		return "", fmt.Errorf("%w: no mutations given", ErrInvalidMutation)
	}
	sealed, err := parseSealedSecret(sealedYAML)
	if err != nil {
		return "", err
	}
	// spec.template.data is unauthenticated and overrides sealed values at unseal; spec.data is one
	// opaque legacy blob holding every entry. Neither can be edited key by key.
	if len(sealed.Spec.Template.Data) > 0 {
		return "", fmt.Errorf("%w: spec.template.data is not editable key by key", ErrInvalidMutation)
	}
	if len(sealed.Spec.Data) > 0 {
		return "", fmt.Errorf("%w: spec.data is a single legacy blob and cannot be edited key by key", ErrInvalidMutation)
	}

	present := make(map[string]bool, len(sealed.Spec.EncryptedData))
	for key := range sealed.Spec.EncryptedData {
		present[key] = true
	}
	if err := validateMutations(mutations, present, len(present)); err != nil {
		return "", err
	}

	var pubKey *rsa.PublicKey
	for _, m := range mutations {
		if m.Op == ResealDelete {
			delete(sealed.Spec.EncryptedData, m.Key)
			continue
		}
		if pubKey == nil {
			if w.cert == nil {
				return "", fmt.Errorf("crypto: no certificate provider configured")
			}
			cert, certErr := w.cert.Get(ctx)
			if certErr != nil {
				return "", fmt.Errorf("crypto: fetch cert: %w", certErr)
			}
			var ok bool
			pubKey, ok = cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				return "", fmt.Errorf("crypto: cert public key is not RSA (got %T)", cert.PublicKey)
			}
		}
		// Seal through the library so the strict-scope label is derived exactly as kubeseal derives it.
		one, sealErr := ssv1alpha1.NewSealedSecret(w.codecs, pubKey, &corev1.Secret{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{Name: sealed.Name, Namespace: sealed.Namespace, Annotations: sealed.Annotations},
			StringData: map[string]string{m.Key: m.Value},
		})
		if sealErr != nil {
			return "", fmt.Errorf("crypto: seal key %q: %w", m.Key, sealErr)
		}
		value, ok := one.Spec.EncryptedData[m.Key]
		if !ok {
			return "", fmt.Errorf("crypto: seal key %q: no ciphertext produced", m.Key)
		}
		sealed.Spec.EncryptedData[m.Key] = value
	}

	// Server-owned fields are not part of the manifest written to Git.
	sealed.Status = ssv1alpha1.SealedSecret{}.Status
	sealed.ResourceVersion = ""
	sealed.UID = ""
	sealed.Generation = 0
	sealed.CreationTimestamp = metav1.Time{}
	sealed.DeletionTimestamp = nil
	sealed.ManagedFields = nil
	return encodeSealedSecret(sealed, w.codecs)
}

// ExtractKeys lists key names without decrypting, so the UI can offer targets without values.
func (w *Wrapper) ExtractKeys(yamlStr string) ([]string, error) {
	ss, err := parseSealedSecret(yamlStr)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(ss.Spec.EncryptedData))
	for k := range ss.Spec.EncryptedData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (w *Wrapper) ValidateSealedSecretYAML(yamlStr string) error {
	_, err := parseSealedSecret(yamlStr)
	return err
}

// parseSealedSecret uses YAMLOrJSONDecoder; the scheme's UniversalDecoder has no internal version for bitnami.com.
func parseSealedSecret(yamlStr string) (*ssv1alpha1.SealedSecret, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(yamlStr), 4096)
	var ss ssv1alpha1.SealedSecret
	if err := decoder.Decode(&ss); err != nil {
		return nil, fmt.Errorf("crypto: decode sealed secret: %w", err)
	}
	if ss.Kind == "" || ss.Kind != "SealedSecret" {
		return nil, fmt.Errorf("crypto: input is not a SealedSecret (got kind %q)", ss.Kind)
	}
	return &ss, nil
}

// mutateSecretYAML applies a mutation batch and returns the updated YAML plus the Secret's sealing scope.
func mutateSecretYAML(secretYAML string, mutations []Mutation, codecs serializer.CodecFactory) (string, Scope, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(secretYAML), 4096)
	var secret corev1.Secret
	if err := decoder.Decode(&secret); err != nil {
		return "", StrictScope, fmt.Errorf("crypto: decode secret for mutation: %w", err)
	}

	data := map[string]string{}
	for k, v := range secret.Data {
		data[k] = string(v)
	}
	for k, v := range secret.StringData {
		data[k] = v
	}

	present := make(map[string]bool, len(data))
	for k := range data {
		present[k] = true
	}
	if err := validateMutations(mutations, present, len(data)); err != nil {
		return "", StrictScope, err
	}

	for _, m := range mutations {
		if m.Op == ResealDelete {
			delete(data, m.Key)
			continue
		}
		data[m.Key] = m.Value
	}

	mutated := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		// These fields carry the sealing scope; the rest of ObjectMeta belongs to the live object.
		ObjectMeta: metav1.ObjectMeta{
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			Labels:          secret.Labels,
			Annotations:     secret.Annotations,
			OwnerReferences: secret.OwnerReferences,
		},
		Type:       secret.Type,
		Immutable:  secret.Immutable,
		StringData: data,
	}

	var buf bytes.Buffer
	if err := codecs.LegacyCodec(corev1.SchemeGroupVersion).Encode(mutated, &buf); err != nil {
		return "", StrictScope, fmt.Errorf("crypto: encode mutated secret: %w", err)
	}
	return buf.String(), scopeFromAnnotations(secret.Annotations), nil
}

// Deletions count against the pre-batch key set, so a delete-then-add batch stays valid.
func validateMutations(mutations []Mutation, present map[string]bool, startingCount int) error {
	finalCount := startingCount
	seen := make(map[string]bool, len(mutations))
	for _, m := range mutations {
		if m.Key == "" {
			return fmt.Errorf("%w: mutation has an empty key", ErrInvalidMutation)
		}
		if seen[m.Key] {
			return fmt.Errorf("%w: key %q appears twice in one batch", ErrInvalidMutation, m.Key)
		}
		seen[m.Key] = true
		switch m.Op {
		case ResealAdd:
			// Delete stays unvalidated: a pre-rule Secret may carry a bad key, and removing it must work.
			if msgs := validation.IsConfigMapKey(m.Key); len(msgs) > 0 {
				return fmt.Errorf("%w: key %q is not a valid Secret key: %s", ErrInvalidMutation, m.Key, msgs[0])
			}
			if present[m.Key] {
				return fmt.Errorf("%w: key %q already exists (use replace)", ErrInvalidMutation, m.Key)
			}
			finalCount++
		case ResealReplace:
			if msgs := validation.IsConfigMapKey(m.Key); len(msgs) > 0 {
				return fmt.Errorf("%w: key %q is not a valid Secret key: %s", ErrInvalidMutation, m.Key, msgs[0])
			}
			if !present[m.Key] {
				return fmt.Errorf("%w: key %q does not exist (use add)", ErrInvalidMutation, m.Key)
			}
		case ResealDelete:
			if !present[m.Key] {
				return fmt.Errorf("%w: key %q does not exist", ErrInvalidMutation, m.Key)
			}
			finalCount--
		default:
			return fmt.Errorf("%w: unknown operation %q", ErrInvalidMutation, m.Op)
		}
	}
	if finalCount < 1 {
		return fmt.Errorf("%w: cannot delete the final key", ErrInvalidMutation)
	}
	return nil
}

// scopeFromAnnotations asks the library which annotations each scope writes, so a rename upstream cannot silently downgrade edited Secrets to strict.
func scopeFromAnnotations(annotations map[string]string) Scope {
	// Cluster-wide first: the wider reading is the safe one if both annotations appear.
	for _, scope := range []Scope{ClusterWideScope, NamespaceWideScope} {
		probe := map[string]string{}
		ssv1alpha1.UpdateScopeAnnotations(probe, scope.SealingScope())
		matched := len(probe) > 0
		for key, want := range probe {
			if annotations[key] != want {
				matched = false
				break
			}
		}
		if matched {
			return scope
		}
	}
	return StrictScope
}

// NewTestCrypto builds a Wrapper around a generated RSA keypair for round-trip tests.
func NewTestCrypto() (*Wrapper, *rsa.PrivateKey, error) {
	privKey, cert, err := crypto.GeneratePrivateKeyAndCert(2048, 365*24*3600, "test-controller")
	if err != nil {
		return nil, nil, fmt.Errorf("generate key+cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("generated cert public key is not RSA")
	}

	return New(
		&staticCertProvider{cert: cert, pub: pubKey, pem: string(certPEM)},
		&staticPrivProvider{key: privKey},
	), privKey, nil
}

// SecretYAML builds a minimal Secret YAML for testing.
func SecretYAML(name, namespace string, data map[string]string, secretType string) string {
	if secretType == "" {
		secretType = "Opaque"
	}
	var sb strings.Builder
	sb.WriteString("apiVersion: v1\n")
	sb.WriteString("kind: Secret\n")
	fmt.Fprintf(&sb, "metadata:\n  name: %s\n  namespace: %s\n", name, namespace)
	fmt.Fprintf(&sb, "type: %s\n", secretType)
	if len(data) > 0 {
		sb.WriteString("stringData:\n")
		for k, v := range data {
			fmt.Fprintf(&sb, "  %s: %s\n", k, v)
		}
	}
	return sb.String()
}

// staticCertProvider is a test Provider returning a fixed certificate.
type staticCertProvider struct {
	cert *x509.Certificate
	pub  *rsa.PublicKey
	pem  string
}

func (f *staticCertProvider) Get(_ context.Context) (*x509.Certificate, error) {
	return f.cert, nil
}

type staticPrivProvider struct {
	key *rsa.PrivateKey
}

func (f *staticPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	return []*rsa.PrivateKey{f.key}, nil
}

// Keeps the kubeseal and runtime imports referenced.
var (
	_                = kubeseal.Seal
	_ runtime.Object = &ssv1alpha1.SealedSecret{}
)
