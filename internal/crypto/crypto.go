// Package crypto wraps the Sealed Secrets encryption and decryption primitives
// in-process — it never shells out to the kubeseal binary. Encryption needs a Provider
// for the controller's public certificate; decryption additionally needs a
// PrivateKeyProvider and is reachable only when ENABLE_DECRYPT=true.
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

// PrivateKeyProvider supplies the controller's RSA private keys for decryption. It must
// return every key the controller still holds: a SealedSecret sealed before a key
// rotation can only be opened by the key that sealed it, not by the current active key.
type PrivateKeyProvider interface {
	PrivateKeys(ctx context.Context) ([]*rsa.PrivateKey, error)
}

// Wrapper encrypts, decrypts, and reseals in-process. All methods are safe for
// concurrent use.
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

// EncryptYAML seals a raw k8s Secret YAML into SealedSecret YAML. The scope pins how
// tightly the result is bound to a namespace/name.
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

	// The encryption label derives from the scope annotations on the input Secret, so the
	// scope must be set BEFORE sealing: annotating the SealedSecret afterwards produces a
	// label mismatch on unseal.
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
	if err = encoder.Encode(sealed, &buf); err != nil {
		return "", fmt.Errorf("crypto: encode sealed secret: %w", err)
	}
	// The codec writes JSON. The repository stores YAML, and a one-line JSON document
	// would make every edit a diff of the whole file, so the output is converted — the
	// same rendering the kubeseal CLI writes.
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
	// Render as stringData so the output is human-readable and matches the kubeseal
	// CLI's unseal output.
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

// privateKeyMap indexes every controller key by its public-key fingerprint; Unseal looks
// the sealing key up per encrypted value, so secrets sealed before a rotation still open
// as long as the provider supplies the key that sealed them.
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

// ErrInvalidMutation marks a batch the caller got wrong — an unknown operation, a key
// that does not exist, an add over a key that does, or a batch that would empty the
// Secret — so a handler can answer 4xx instead of blaming the backend.
var ErrInvalidMutation = errors.New("crypto: invalid mutation")

// ResealMany applies a batch of mutations to an existing SealedSecret in one pass:
// decrypt internally, apply every change, re-encrypt once. Only the values the caller
// supplies are accepted; the batch is validated whole before anything is applied.
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

	// Re-seal at the scope the Secret already carried, never a default: a namespace-wide
	// Secret re-sealed as strict stops decrypting outside its own namespace, and a
	// cluster-wide one stops decrypting anywhere else.
	return w.EncryptYAML(ctx, updated, "", "", scope)
}

// Reseal is the single-mutation case of ResealMany, routed through it so both share one
// implementation and one set of rules.
func (w *Wrapper) Reseal(ctx context.Context, sealedYAML, key, newValue string, op ResealOp) (string, error) {
	return w.ResealMany(ctx, sealedYAML, []Mutation{{Key: key, Value: newValue, Op: op}})
}

// ExtractKeys lists a SealedSecret's key names without decrypting, so the UI can offer
// targets for reveal or patch without exposing values.
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

// parseSealedSecret uses a YAMLOrJSONDecoder rather than the scheme's UniversalDecoder,
// which has no internal version for bitnami.com.
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

// mutateSecretYAML applies a batch to a Secret's data and returns the updated YAML and the
// sealing scope the Secret already carried. Every mutation is validated against the key set
// as it stood before the batch, not against the state left by earlier entries, so the
// outcome cannot depend on the order the client sent; nothing is applied until all pass.
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
	// Deletions count against the starting state too, so a batch that would empty the
	// Secret is refused as a whole regardless of the order its entries arrive in.
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
		// Labels, annotations, and owner references are part of the Secret and carry the
		// sealing scope, so a patch must not drop them; the remaining ObjectMeta fields are
		// assigned by the API server to one live object and were never true of the file.
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

// scopeFromAnnotations recovers the sealing scope recorded on a Secret by asking the
// library which annotations each scope writes, rather than restating the keys here where a
// rename would silently downgrade every edited Secret to strict.
func scopeFromAnnotations(annotations map[string]string) Scope {
	// Cluster-wide first: it is the wider grant, so if a Secret somehow carried both
	// annotations the more permissive reading is the safe one to preserve.
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

// NewTestCrypto returns a Wrapper with a generated RSA keypair, so tests can do real
// encrypt/decrypt round trips without a live controller.
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

// Keeps the kubeseal and runtime imports referenced; the compiler would otherwise reject
// them as unused.
var (
	_                = kubeseal.Seal
	_ runtime.Object = &ssv1alpha1.SealedSecret{}
)
