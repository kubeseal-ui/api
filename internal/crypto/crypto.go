// Package crypto wraps the Sealed Secrets encryption and decryption
// primitives. It operates in-process — it NEVER shells out to the
// kubeseal binary. The package is a thin, well-tested abstraction over
// github.com/bitnami-labs/sealed-secrets so the rest of the API can
// depend on stable interfaces and mock implementations.
//
// The crypto wrapper depends on two things provided by the caller:
//
//   - A Provider for the public certificate (used for encryption).
//   - A PrivateKeyProvider for the controller private key (used for
//     decryption only, and only when ENABLE_DECRYPT=true).
//
// NewTestCrypto returns a Wrapper with a generated RSA keypair so
// unit tests can do real encrypt->decrypt round trips without a live
// controller or HTTP cert endpoint.
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
	"k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

// Scope defines the mobility of a sealed secret.
type Scope int

const (
	StrictScope        Scope = Scope(ssv1alpha1.StrictScope)
	NamespaceWideScope Scope = Scope(ssv1alpha1.NamespaceWideScope)
	ClusterWideScope   Scope = Scope(ssv1alpha1.ClusterWideScope)
)

// String returns the human-readable name for a Scope.
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

// Set parses a scope string into a Scope. Required for flag.Value.
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

// Type returns the type name for flag.Value.
func (s *Scope) Type() string { return "scope" }

// SealingScope converts our Scope to the library type.
func (s Scope) SealingScope() ssv1alpha1.SealingScope {
	return ssv1alpha1.SealingScope(s)
}

// Provider returns the active public certificate used for encryption.
type Provider interface {
	Get(ctx context.Context) (*x509.Certificate, error)
}

// PrivateKeyProvider returns the controller RSA private keys for
// decryption. Only available in decrypt-enabled mode. Implementations
// MUST return every key the controller still holds: the sealed-secrets
// controller rotates its sealing key on a schedule, and a SealedSecret
// sealed before a rotation can only be opened by the key that sealed
// it, not by the current active key.
type PrivateKeyProvider interface {
	PrivateKeys(ctx context.Context) ([]*rsa.PrivateKey, error)
}

// Wrapper provides in-process Sealed Secrets encryption, decryption,
// and resealing. All methods are safe for concurrent use.
type Wrapper struct {
	cert   Provider
	priv   PrivateKeyProvider
	codecs serializer.CodecFactory
}

// New constructs a crypto Wrapper from the given providers.
// priv may be nil if decryption is disabled.
func New(cert Provider, priv PrivateKeyProvider) *Wrapper {
	codecs := serializer.NewCodecFactory(scheme.Scheme)
	return &Wrapper{
		cert:   cert,
		priv:   priv,
		codecs: codecs,
	}
}

// EncryptYAML takes a raw k8s Secret YAML document and returns the
// encrypted SealedSecret YAML. The scope determines how tightly the
// sealed secret is pinned to a namespace/name.
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

	// The encryption label derives from the scope annotations on the
	// input Secret (see ssv1alpha1.labelFor), so the scope must be set
	// on the Secret BEFORE sealing — annotating the SealedSecret after
	// the fact produces a label mismatch on unseal.
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

	var buf bytes.Buffer
	encoder := w.codecs.LegacyCodec(ssv1alpha1.SchemeGroupVersion)
	if err := encoder.Encode(sealed, &buf); err != nil {
		return "", fmt.Errorf("crypto: encode sealed secret: %w", err)
	}

	return buf.String(), nil
}

// DecryptYAML takes a SealedSecret YAML document and returns the
// decrypted Secret YAML. Requires the private-key provider.
func (w *Wrapper) DecryptYAML(ctx context.Context, sealedYAML string) (string, error) {
	if w.priv == nil {
		return "", fmt.Errorf("crypto: decrypt is disabled (ENABLE_DECRYPT=false)")
	}

	privKeys, err := w.privateKeyMap(ctx)
	if err != nil {
		return "", err
	}

	sealed, err := parseSealedSecret(sealedYAML)
	if err != nil {
		return "", err
	}

	secret, err := sealed.Unseal(w.codecs, privKeys)
	if err != nil {
		return "", fmt.Errorf("crypto: unseal: %w", err)
	}
	// Render values as plaintext stringData so the YAML output is
	// human-readable and matches the kubeseal CLI's unseal output.
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

// privateKeyMap indexes every controller key by its public-key
// fingerprint. Unseal looks the sealing key up per encrypted value, so
// secrets sealed before a controller key rotation still decrypt as long
// as the provider still supplies the key that sealed them.
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

// ResealOp is the mutation operation for Reseal and ResealMany.
type ResealOp string

const (
	ResealReplace ResealOp = "replace"
	ResealAdd     ResealOp = "add"
	ResealDelete  ResealOp = "delete"
)

// ErrInvalidMutation marks a batch the caller got wrong rather than one this
// package failed to carry out: an unknown operation, a key that does not exist,
// an add over a key that does, or a batch that would empty the Secret. It is
// deliberately separate from a decryption or encoding failure so a handler can
// answer with a 4xx instead of blaming the backend for the caller's mistake.
var ErrInvalidMutation = errors.New("crypto: invalid mutation")

// ResealMany mutates any number of keys in an existing SealedSecret in one
// pass: decrypt internally, apply every mutation, re-encrypt once, and return
// the new SealedSecret YAML. Only the values the caller supplies are accepted;
// unrelated values are never exposed.
//
// A batch is one reviewed change and one commit, so it is validated before
// anything is applied and either lands whole or not at all. See
// mutateSecretYAML for the validation rules.
func (w *Wrapper) ResealMany(ctx context.Context, sealedYAML string, mutations []Mutation) (string, error) {
	if w.priv == nil {
		return "", fmt.Errorf("crypto: decrypt is disabled (ENABLE_DECRYPT=false)")
	}
	if len(mutations) == 0 {
		return "", fmt.Errorf("%w: no mutations given", ErrInvalidMutation)
	}

	secretYAML, err := w.DecryptYAML(ctx, sealedYAML)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt for reseal: %w", err)
	}

	updated, scope, err := mutateSecretYAML(secretYAML, mutations, w.codecs)
	if err != nil {
		return "", err
	}

	// The scope is the one the Secret already carried, not a default. Re-sealing
	// at the wrong scope is not cosmetic: a namespace-wide Secret re-sealed as
	// strict stops decrypting outside its own namespace, and a cluster-wide one
	// stops decrypting anywhere else.
	return w.EncryptYAML(ctx, updated, "", "", scope)
}

// Reseal mutates one key in an existing SealedSecret. It is the single-mutation
// case of ResealMany — kept as its own entry point because most callers change
// one key, and routed through ResealMany so there is one implementation and one
// set of rules rather than two that can drift apart.
func (w *Wrapper) Reseal(ctx context.Context, sealedYAML, key, newValue string, op ResealOp) (string, error) {
	return w.ResealMany(ctx, sealedYAML, []Mutation{{Key: key, Value: newValue, Op: op}})
}

// ExtractKeys returns the key names from a SealedSecret's encrypted data
// without decrypting. This lets the UI show which keys exist in the secret
// so the user can pick a target for reveal/patch without exposing values.
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

// ValidateSealedSecretYAML verifies that the given YAML parses as a
// valid SealedSecret. Used by callers to validate before returning.
func (w *Wrapper) ValidateSealedSecretYAML(yamlStr string) error {
	_, err := parseSealedSecret(yamlStr)
	return err
}

// parseSealedSecret decodes a SealedSecret from YAML into a typed
// object, mirroring the sealed-secrets CLI's readSealedSecrets which
// uses a YAMLOrJSONDecoder rather than the scheme's UniversalDecoder
// (client-go's scheme has no internal version for bitnami.com).
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

// mutateSecretYAML applies a batch of mutations to a Secret YAML's data and
// returns the updated YAML along with the sealing scope the Secret already
// carried.
//
// Every mutation is validated against the key set as it stood *before* the
// batch, not against the state left by earlier mutations in the same batch. A
// batch is one reviewed change, so it reads as a single description of the
// finished Secret rather than as a sequence — which also means the outcome
// cannot depend on the order the client happened to send, and a batch naming
// the same key twice is refused rather than silently resolving to whichever
// entry came last.
//
// Validation is complete before anything is applied, so a refused batch leaves
// no partial mutation behind: the caller either gets a fully mutated Secret or
// an error and the original.
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
	// Deletions are counted against the starting state too, so a batch that
	// would empty the Secret is refused as a whole rather than succeeding or
	// failing depending on the order its entries arrive in.
	finalCount := len(data)
	seen := make(map[string]bool, len(mutations))
	for _, m := range mutations {
		if m.Key == "" {
			return "", StrictScope, fmt.Errorf("%w: mutation has an empty key", ErrInvalidMutation)
		}
		if seen[m.Key] {
			return "", StrictScope, fmt.Errorf("%w: key %q appears twice in one batch", ErrInvalidMutation, m.Key)
		}
		seen[m.Key] = true
		switch m.Op {
		case ResealAdd:
			if present[m.Key] {
				return "", StrictScope, fmt.Errorf("%w: key %q already exists (use replace)", ErrInvalidMutation, m.Key)
			}
			finalCount++
		case ResealReplace:
			if !present[m.Key] {
				return "", StrictScope, fmt.Errorf("%w: key %q does not exist (use add)", ErrInvalidMutation, m.Key)
			}
		case ResealDelete:
			if !present[m.Key] {
				return "", StrictScope, fmt.Errorf("%w: key %q does not exist", ErrInvalidMutation, m.Key)
			}
			if finalCount <= 1 {
				return "", StrictScope, fmt.Errorf("%w: cannot delete the final key", ErrInvalidMutation)
			}
			finalCount--
		default:
			return "", StrictScope, fmt.Errorf("%w: unknown operation %q", ErrInvalidMutation, m.Op)
		}
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
		// Labels, annotations, and owner references are part of what the Secret
		// is, and a patch that quietly dropped them would change the object far
		// beyond the key it was asked to edit — the annotations also carry the
		// sealing scope. The remaining ObjectMeta fields (uid, resourceVersion,
		// generation, creationTimestamp, managedFields, selfLink) are assigned
		// by the API server to one live object, so carrying them into a manifest
		// would record something that was never true of the file.
		ObjectMeta: metav1.ObjectMeta{
			Name:            secret.Name,
			Namespace:       secret.Namespace,
			Labels:          secret.Labels,
			Annotations:     secret.Annotations,
			OwnerReferences: secret.OwnerReferences,
		},
		Type:       secret.Type,
		StringData: data,
	}

	var buf bytes.Buffer
	if err := codecs.LegacyCodec(corev1.SchemeGroupVersion).Encode(mutated, &buf); err != nil {
		return "", StrictScope, fmt.Errorf("crypto: encode mutated secret: %w", err)
	}
	return buf.String(), scopeFromAnnotations(secret.Annotations), nil
}

// scopeFromAnnotations recovers the sealing scope recorded on a Secret.
//
// The annotation keys are the library's to choose, so rather than restating
// them here — where a rename would silently downgrade every edited Secret to
// strict — this asks the library which annotation each scope writes, using the
// same UpdateScopeAnnotations call EncryptYAML already relies on.
func scopeFromAnnotations(annotations map[string]string) Scope {
	// Cluster-wide first: it is the wider grant, so if a Secret somehow carried
	// both annotations the more permissive reading is the safe one to preserve.
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

// ---- test helpers ----

// NewTestCrypto returns a Wrapper with a generated RSA keypair so
// unit tests can do real encrypt->decrypt round trips without a live
// controller or HTTP cert endpoint.
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

// staticCertProvider is a test Provider that returns a fixed certificate.
type staticCertProvider struct {
	cert *x509.Certificate
	pub  *rsa.PublicKey
	pem  string
}

func (f *staticCertProvider) Get(_ context.Context) (*x509.Certificate, error) {
	return f.cert, nil
}

// staticPrivProvider is a test PrivateKeyProvider that returns a fixed key.
type staticPrivProvider struct {
	key *rsa.PrivateKey
}

func (f *staticPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	return []*rsa.PrivateKey{f.key}, nil
}

// Ensure kubeseal import is referenced — used for Seal/SealedSecret
// integration in future phases.
var (
	_                = kubeseal.Seal
	_ runtime.Object = &ssv1alpha1.SealedSecret{}
)
