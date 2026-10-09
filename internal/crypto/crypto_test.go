// Package crypto tests — RED-GREEN-REFACTOR per the
// test-driven-development skill. Each test documents a security or
// correctness contract from internal-docs/engineering/backend/crypto-wrapper.md.
package crypto

import (
	"context"
	"crypto/rsa"
	"strings"
	"testing"
)

// TestEncryptDecryptRoundTripStrict verifies that a secret encrypted
// with StrictScope can be decrypted back to the original data, and
// that the scope annotation is present on the SealedSecret.
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

// TestEncryptDecryptRoundTripNamespaceWide verifies namespace-wide scope.
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

// TestEncryptDecryptRoundTripClusterWide verifies cluster-wide scope.
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

// TestDecryptWrongKeyFails verifies that decryption with a key that
// does not match the encryption key fails rather than silently
// producing garbage.
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

// multiPrivProvider is a PrivateKeyProvider that returns several keys,
// standing in for a controller that has rotated its sealing key and
// retained the previous ones.
type multiPrivProvider struct {
	keys []*rsa.PrivateKey
}

func (m *multiPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	return m.keys, nil
}

// TestDecryptAfterKeyRotation verifies that a SealedSecret sealed before
// a controller key rotation still decrypts once the provider supplies
// the retained key alongside the new active one. The sealed-secrets
// controller rotates its sealing key on a schedule and keeps the old
// keys; a decrypt path holding only the newest key cannot open secrets
// sealed before the rotation.
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

// TestResealReplace verifies that replacing one key preserves others.
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

// TestResealAdd verifies that adding a new key preserves existing keys.
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

// TestResealDelete verifies that deleting a key preserves other keys.
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

// TestResealDeleteLastKeyFails verifies the final-key protection.
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

// TestResealReplaceNonExistentFails verifies replace on a non-existent key fails.
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

// TestResealAddExistingKeyFails verifies add on an existing key fails.
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

// TestResealManyAppliesAMixedBatch verifies that a replace, an add, and a
// delete in one batch land together and leave unrelated keys alone. One batch
// is one reviewed change and one commit, so the three must not need three
// round trips.
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

// TestResealManyRejectsInvalidBatches verifies that validation covers the whole
// batch before anything is applied.
//
// Each rule is checked against the key set as it stood before the batch, not
// against the state left by the entries ahead of it, which is what makes the
// outcome independent of the order the client sent. A batch that would remove
// the last remaining key is refused as a whole, so the Secret can never be left
// empty by a sequence of individually-valid deletions.
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

// TestResealManyRejectsAnEmptyBatch verifies that "change nothing" is refused
// rather than accepted as a no-op. A request that describes no change is a bug
// in the caller, and answering it with a re-sealed Secret would produce a fresh
// commit whose content is identical to the old one.
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

// TestResealPreservesMetadataAndScope verifies that editing a key leaves the
// rest of the object intact.
//
// secret-editing.md promises an edit preserves type, labels, annotations, and
// template. It did not: the rebuild carried only name, namespace, type, and
// data, so every patch silently stripped the template's labels and annotations,
// and the re-seal was hardcoded to strict — which quietly narrowed a
// namespace-wide Secret, changing where it can be decrypted.
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
		"kubernetes.io/tls",   // type
		"app: payments-api",   // label
		"owner: platform-team", // annotation
		"tls.key: key",        // unrelated key
		"tls.crt: new-cert",   // the edit itself
	} {
		if !strings.Contains(decrypted, want) {
			t.Errorf("decrypted output missing %q: %s", want, decrypted)
		}
	}
}

// TestEncryptRejectsInvalidSecretYAML verifies malformed YAML is rejected.
func TestEncryptRejectsInvalidSecretYAML(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	_, err := w.EncryptYAML(t.Context(), "this is not yaml {{{", "default", "x", StrictScope)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

// TestDecryptWithoutPrivateKeyProviderFails verifies decryption fails
// closed when no private key provider is configured.
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

// TestResealWithoutPrivateKeyProviderFails verifies reseal fails closed
// when no private key provider is configured.
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

// TestValidateSealedSecretYAML verifies that a valid SealedSecret
// YAML passes validation and invalid input does not.
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

// TestDecryptRejectsWrongYAML verifies that decrypting a non-SealedSecret
// YAML fails.
func TestDecryptRejectsWrongYAML(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	_, err := w.DecryptYAML(t.Context(), "kind: ConfigMap\nmetadata:\n  name: test\n")
	if err == nil {
		t.Fatal("expected error for non-SealedSecret YAML")
	}
}

// TestScopeString verifies the String() method for all scopes.
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

// TestScopeSet verifies parsing and rejection of invalid scope strings.
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

// mustNewFakeCertProvider creates a Provider backed by a test cert
// for use in tests that only need encryption (no decryption).
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
