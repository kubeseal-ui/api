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
	"fmt"
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

// PrivateKeyProvider returns the controller RSA private key for
// decryption. Only available in decrypt-enabled mode.
type PrivateKeyProvider interface {
	PrivateKey(ctx context.Context) (*rsa.PrivateKey, error)
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

	privKey, err := w.priv.PrivateKey(ctx)
	if err != nil {
		return "", fmt.Errorf("crypto: fetch private key: %w", err)
	}

	sealed, err := parseSealedSecret(sealedYAML)
	if err != nil {
		return "", err
	}

	fp, err := crypto.PublicKeyFingerprint(&privKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("crypto: fingerprint key: %w", err)
	}
	privKeys := map[string]*rsa.PrivateKey{fp: privKey}

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

// Reseal mutates one key in an existing SealedSecret: decrypt internally,
// apply the mutation (replace/add/delete), re-encrypt, and return the
// new SealedSecret YAML. Only the requested key's new value is accepted
// from the caller; unrelated values are never exposed.
func (w *Wrapper) Reseal(ctx context.Context, sealedYAML, key, newValue string, op ResealOp) (string, error) {
	if w.priv == nil {
		return "", fmt.Errorf("crypto: decrypt is disabled (ENABLE_DECRYPT=false)")
	}

	secretYAML, err := w.DecryptYAML(ctx, sealedYAML)
	if err != nil {
		return "", fmt.Errorf("crypto: decrypt for reseal: %w", err)
	}

	updated, err := mutateSecretYAML(secretYAML, key, newValue, op, w.codecs)
	if err != nil {
		return "", err
	}

	return w.EncryptYAML(ctx, updated, "", "", StrictScope)
}

// ResealOp is the mutation operation for Reseal.
type ResealOp string

const (
	ResealReplace ResealOp = "replace"
	ResealAdd     ResealOp = "add"
	ResealDelete  ResealOp = "delete"
)

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

// mutateSecretYAML applies one mutation (replace/add/delete) to a
// Secret YAML's stringData and returns the updated YAML string.
func mutateSecretYAML(secretYAML, key, newValue string, op ResealOp, codecs serializer.CodecFactory) (string, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(secretYAML), 4096)
	var secret corev1.Secret
	if err := decoder.Decode(&secret); err != nil {
		return "", fmt.Errorf("crypto: decode secret for mutation: %w", err)
	}

	data := map[string]string{}
	for k, v := range secret.Data {
		data[k] = string(v)
	}
	for k, v := range secret.StringData {
		data[k] = v
	}

	switch op {
	case ResealAdd:
		if _, exists := data[key]; exists {
			return "", fmt.Errorf("crypto: key %q already exists (use replace)", key)
		}
		data[key] = newValue
	case ResealReplace:
		if _, exists := data[key]; !exists {
			return "", fmt.Errorf("crypto: key %q does not exist (use add)", key)
		}
		data[key] = newValue
	case ResealDelete:
		if _, exists := data[key]; !exists {
			return "", fmt.Errorf("crypto: key %q does not exist", key)
		}
		if len(data) <= 1 {
			return "", fmt.Errorf("crypto: cannot delete the final key")
		}
		delete(data, key)
	default:
		return "", fmt.Errorf("crypto: unknown operation %q", op)
	}

	mutated := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secret.Name,
			Namespace: secret.Namespace,
		},
		Type:       secret.Type,
		StringData: data,
	}

	var buf bytes.Buffer
	if err := codecs.LegacyCodec(corev1.SchemeGroupVersion).Encode(mutated, &buf); err != nil {
		return "", fmt.Errorf("crypto: encode mutated secret: %w", err)
	}
	return buf.String(), nil
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

func (f *staticPrivProvider) PrivateKey(_ context.Context) (*rsa.PrivateKey, error) {
	return f.key, nil
}

// Ensure kubeseal import is referenced — used for Seal/SealedSecret
// integration in future phases.
var (
	_                = kubeseal.Seal
	_ runtime.Object = &ssv1alpha1.SealedSecret{}
)
