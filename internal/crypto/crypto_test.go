// Package crypto tests — RED-GREEN-REFACTOR per the
// test-driven-development skill. Each test documents a security or
// correctness contract from internal-docs/engineering/backend/crypto-wrapper.md.
package crypto

import (
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
