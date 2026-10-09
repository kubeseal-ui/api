package crypto

import (
	"context"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTripStrict(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("my-secret", "default", map[string]string{
		"username": "admin",
		"password": "hunter2",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "my-secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}
	if !strings.Contains(sealed, "SealedSecret") {
		t.Fatalf("output is not a SealedSecret: %s", sealed)
	}

	decrypted, err := w.DecryptYAML(t.Context(), sealed)
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}
	if !strings.Contains(decrypted, "username: admin") {
		t.Errorf("decrypted output missing username: %s", decrypted)
	}
	if !strings.Contains(decrypted, "password: hunter2") {
		t.Errorf("decrypted output missing password: %s", decrypted)
	}
}

// TestEncryptYAMLWritesYAML pins the manifest format: every manifest a client sees comes
// from EncryptYAML and is committed verbatim, and JSON is a valid YAML subset, so a
// one-line JSON document would parse and reconcile while breaking every diff.
func TestEncryptYAMLWritesYAML(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("tet", "immich", map[string]string{"password": "hunter2"}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "immich", "tet", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	// The same document rendered as JSON is one line, so a first-line check distinguishes
	// them rather than a substring both forms contain.
	if !strings.HasPrefix(sealed, "apiVersion:") {
		t.Fatalf("sealed manifest does not begin with a YAML key:\n%s", sealed)
	}
	if lines := strings.Split(strings.TrimSpace(sealed), "\n"); len(lines) < 5 {
		t.Fatalf("sealed manifest is %d line(s), want a multi-line YAML document:\n%s", len(lines), sealed)
	}
	if !strings.Contains(sealed, "\nkind: SealedSecret\n") {
		t.Fatalf("sealed manifest does not carry kind on its own line:\n%s", sealed)
	}
	// The rendering also has to be the document the controller reads back.
	if _, err := parseSealedSecret(sealed); err != nil {
		t.Fatalf("the YAML rendering does not parse as a SealedSecret: %v", err)
	}
}

func TestEncryptDecryptRoundTripNamespaceWide(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("ns-secret", "payments", map[string]string{
		"api_key": "key123",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "payments", "ns-secret", NamespaceWideScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), sealed)
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}
	if !strings.Contains(decrypted, "api_key: key123") {
		t.Errorf("decrypted output missing api_key: %s", decrypted)
	}
}

func TestEncryptDecryptRoundTripClusterWide(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("cluster-secret", "default", map[string]string{
		"root": "admin",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "cluster-secret", ClusterWideScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), sealed)
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}
	if !strings.Contains(decrypted, "root: admin") {
		t.Errorf("decrypted output missing root: %s", decrypted)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	w1, _ := mustNewTestCrypto(t)
	w2, _ := mustNewTestCrypto(t) // different key

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "val"}, "")

	sealed, err := w1.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	_, err = w2.DecryptYAML(t.Context(), sealed)
	if err == nil {
		t.Fatal("expected decryption with wrong key to fail, got nil")
	}
}

// multiPrivProvider stands in for a controller that rotated its sealing key and kept the
// previous ones.
type multiPrivProvider struct {
	keys []*rsa.PrivateKey
}

func (m *multiPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	return m.keys, nil
}

// TestDecryptAfterKeyRotation pins the retained-key contract: the controller rotates its
// sealing key on a schedule and keeps the old ones, so a decrypt path holding only the
// newest key cannot open secrets sealed before the rotation.
func TestDecryptAfterKeyRotation(t *testing.T) {
	w1, oldKey := mustNewTestCrypto(t) // key that sealed the secret
	w2, newKey := mustNewTestCrypto(t) // active key after rotation

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "val"}, "")
	sealedBeforeRotation, err := w1.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	// With only the rotated-in key the secret cannot be opened...
	activeOnly := New(w2.cert, &multiPrivProvider{keys: []*rsa.PrivateKey{newKey}})
	if _, err := activeOnly.DecryptYAML(t.Context(), sealedBeforeRotation); err == nil {
		t.Fatal("expected decryption with only the rotated-in key to fail, got nil")
	}

	// ...and succeeds once the retained key is supplied too.
	rotated := New(w2.cert, &multiPrivProvider{keys: []*rsa.PrivateKey{newKey, oldKey}})
	decrypted, err := rotated.DecryptYAML(t.Context(), sealedBeforeRotation)
	if err != nil {
		t.Fatalf("DecryptYAML with retained key: %v", err)
	}
	if !strings.Contains(decrypted, "key: val") {
		t.Errorf("decrypted output missing value: %s", decrypted)
	}
}

func TestResealReplace(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"key1": "value1",
		"key2": "value2",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	resealed, err := w.Reseal(t.Context(), sealed, "key2", "new-value2", ResealReplace)
	if err != nil {
		t.Fatalf("Reseal: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), resealed)
	if err != nil {
		t.Fatalf("DecryptYAML after Reseal: %v", err)
	}
	if !strings.Contains(decrypted, "key1: value1") {
		t.Errorf("unrelated key1 should be preserved: %s", decrypted)
	}
	if !strings.Contains(decrypted, "key2: new-value2") {
		t.Errorf("key2 should be replaced: %s", decrypted)
	}
	if strings.Contains(decrypted, "value2") && !strings.Contains(decrypted, "new-value2") {
		t.Errorf("old value of key2 should not appear: %s", decrypted)
	}
}

func TestResealAdd(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"existing": "old-value",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	resealed, err := w.Reseal(t.Context(), sealed, "new-key", "new-value", ResealAdd)
	if err != nil {
		t.Fatalf("Reseal add: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), resealed)
	if err != nil {
		t.Fatalf("DecryptYAML after Reseal: %v", err)
	}
	if !strings.Contains(decrypted, "existing: old-value") {
		t.Errorf("existing key should be preserved: %s", decrypted)
	}
	if !strings.Contains(decrypted, "new-key: new-value") {
		t.Errorf("new key should be present: %s", decrypted)
	}
}

func TestResealDelete(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"keep":   "keep-val",
		"remove": "remove-val",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	resealed, err := w.Reseal(t.Context(), sealed, "remove", "", ResealDelete)
	if err != nil {
		t.Fatalf("Reseal delete: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), resealed)
	if err != nil {
		t.Fatalf("DecryptYAML after Reseal: %v", err)
	}
	if strings.Contains(decrypted, "remove:") {
		t.Errorf("deleted key should not appear: %s", decrypted)
	}
	if !strings.Contains(decrypted, "keep: keep-val") {
		t.Errorf("other key should be preserved: %s", decrypted)
	}
}

func TestResealDeleteLastKeyFails(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"only": "val",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	_, err = w.Reseal(t.Context(), sealed, "only", "", ResealDelete)
	if err == nil {
		t.Fatal("expected error when deleting the final key")
	}
}

func TestResealReplaceNonExistentFails(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"exists": "val",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	_, err = w.Reseal(t.Context(), sealed, "nonexistent", "val", ResealReplace)
	if err == nil {
		t.Fatal("expected error when replacing non-existent key")
	}
}

func TestResealAddExistingKeyFails(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"exists": "val",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	_, err = w.Reseal(t.Context(), sealed, "exists", "newval", ResealAdd)
	if err == nil {
		t.Fatal("expected error when adding existing key")
	}
}

// One batch is one reviewed change and one commit, so a mixed batch must land in one
// round trip.
func TestResealManyAppliesAMixedBatch(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{
		"keep":   "keep-val",
		"change": "old-val",
		"remove": "remove-val",
	}, "")

	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	resealed, err := w.ResealMany(t.Context(), sealed, []Mutation{
		{Key: "change", Value: "new-val", Op: ResealReplace},
		{Key: "added", Value: "added-val", Op: ResealAdd},
		{Key: "remove", Op: ResealDelete},
	})
	if err != nil {
		t.Fatalf("ResealMany: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), resealed)
	if err != nil {
		t.Fatalf("DecryptYAML after ResealMany: %v", err)
	}
	for _, want := range []string{"keep: keep-val", "change: new-val", "added: added-val"} {
		if !strings.Contains(decrypted, want) {
			t.Errorf("decrypted output missing %q: %s", want, decrypted)
		}
	}
	if strings.Contains(decrypted, "remove:") {
		t.Errorf("deleted key should not appear: %s", decrypted)
	}
}

// TestResealManyRejectsInvalidBatches pins that validation covers the whole batch before
// anything is applied, so the outcome is independent of the order the client sent.
func TestResealManyRejectsInvalidBatches(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{"one": "1", "two": "2"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	cases := []struct {
		name      string
		mutations []Mutation
	}{
		{"duplicate key in one batch", []Mutation{
			{Key: "one", Value: "a", Op: ResealReplace},
			{Key: "one", Value: "b", Op: ResealReplace},
		}},
		{"replace a key that does not exist", []Mutation{{Key: "absent", Value: "a", Op: ResealReplace}}},
		{"add a key that already exists", []Mutation{{Key: "one", Value: "a", Op: ResealAdd}}},
		{"delete a key that does not exist", []Mutation{{Key: "absent", Op: ResealDelete}}},
		{"delete every key", []Mutation{
			{Key: "one", Op: ResealDelete},
			{Key: "two", Op: ResealDelete},
		}},
		{"empty key", []Mutation{{Key: "", Value: "a", Op: ResealAdd}}},
		{"unknown operation", []Mutation{{Key: "one", Value: "a", Op: ResealOp("merge")}}},
	}
	for _, tc := range cases {
		if _, err := w.ResealMany(t.Context(), sealed, tc.mutations); err == nil {
			t.Errorf("%s: expected an error, got nil", tc.name)
		}
	}
}

// A request that describes no change is a caller bug: answering it with a re-sealed
// Secret would commit content identical to the old one.
func TestResealManyRejectsAnEmptyBatch(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "val"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	if _, err := w.ResealMany(t.Context(), sealed, nil); err == nil {
		t.Fatal("expected an error for an empty batch")
	}
}

// TestResealPreservesMetadataAndScope pins that an edit keeps type, labels, annotations,
// template, and the Secret's own sealing scope: hardcoding strict on re-seal quietly
// narrows where a namespace-wide Secret can be decrypted.
func TestResealPreservesMetadataAndScope(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := `apiVersion: v1
kind: Secret
metadata:
  name: secret
  namespace: payments
  labels:
    app: payments-api
  annotations:
    owner: platform-team
type: kubernetes.io/tls
stringData:
  tls.crt: cert
  tls.key: key
`
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "payments", "secret", NamespaceWideScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}
	if !strings.Contains(sealed, "namespace-wide") {
		t.Fatalf("precondition: sealed secret is not namespace-wide: %s", sealed)
	}

	resealed, err := w.Reseal(t.Context(), sealed, "tls.crt", "new-cert", ResealReplace)
	if err != nil {
		t.Fatalf("Reseal: %v", err)
	}

	if !strings.Contains(resealed, "namespace-wide") {
		t.Errorf("scope was not preserved across the edit: %s", resealed)
	}

	decrypted, err := w.DecryptYAML(t.Context(), resealed)
	if err != nil {
		t.Fatalf("DecryptYAML after Reseal: %v", err)
	}
	for _, want := range []string{
		"kubernetes.io/tls",
		"app: payments-api",
		"owner: platform-team",
		"tls.key: key",
		"tls.crt: new-cert",
	} {
		if !strings.Contains(decrypted, want) {
			t.Errorf("decrypted output missing %q: %s", want, decrypted)
		}
	}
}

func TestEncryptRejectsInvalidSecretYAML(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	_, err := w.EncryptYAML(t.Context(), "this is not yaml {{{", "default", "x", StrictScope)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestDecryptWithoutPrivateKeyProviderFails(t *testing.T) {
	w := New(mustNewFakeCertProvider(t), nil)

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "val"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	_, err = w.DecryptYAML(t.Context(), sealed)
	if err == nil {
		t.Fatal("expected decrypt to fail when priv is nil")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected 'disabled' in error, got: %v", err)
	}
}

func TestResealWithoutPrivateKeyProviderFails(t *testing.T) {
	w := New(mustNewFakeCertProvider(t), nil)

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "val"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	_, err = w.Reseal(t.Context(), sealed, "key", "newval", ResealReplace)
	if err == nil {
		t.Fatal("expected reseal to fail when priv is nil")
	}
}

func TestValidateSealedSecretYAML(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "val"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	if err := w.ValidateSealedSecretYAML(sealed); err != nil {
		t.Fatalf("ValidateSealedSecretYAML: %v", err)
	}

	if err := w.ValidateSealedSecretYAML("not a sealed secret"); err == nil {
		t.Fatal("expected validation to fail for invalid input")
	}
}

func TestDecryptRejectsWrongYAML(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	_, err := w.DecryptYAML(t.Context(), "kind: ConfigMap\nmetadata:\n  name: test\n")
	if err == nil {
		t.Fatal("expected error for non-SealedSecret YAML")
	}
}

func TestScopeString(t *testing.T) {
	cases := []struct {
		scope Scope
		want  string
	}{
		{StrictScope, "strict"},
		{NamespaceWideScope, "namespace-wide"},
		{ClusterWideScope, "cluster-wide"},
	}
	for _, tc := range cases {
		if tc.scope.String() != tc.want {
			t.Errorf("scope.String(): want %q, got %q", tc.want, tc.scope.String())
		}
	}
}

func TestScopeSet(t *testing.T) {
	var s Scope
	if err := s.Set("strict"); err != nil {
		t.Fatalf("Set(\"strict\"): %v", err)
	}
	if s != StrictScope {
		t.Errorf("after Set(\"strict\"): want StrictScope, got %v", s)
	}

	if err := s.Set("invalid"); err == nil {
		t.Fatal("expected error for invalid scope")
	}
}

// mustNewFakeCertProvider backs a Provider with a test cert for tests that only encrypt.
func mustNewFakeCertProvider(t *testing.T) Provider {
	t.Helper()
	w, _, err := NewTestCrypto()
	if err != nil {
		t.Fatalf("NewTestCrypto: %v", err)
	}
	return w.cert
}

func mustNewTestCrypto(t *testing.T) (*Wrapper, *rsa.PrivateKey) {
	t.Helper()
	w, privKey, err := NewTestCrypto()
	if err != nil {
		t.Fatalf("NewTestCrypto: %v", err)
	}
	return w, privKey
}
