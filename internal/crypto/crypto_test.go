package crypto

import (
	"context"
	"crypto/rsa"
	"errors"
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

func TestDecryptKeyOnlyOpensRequestedEncryptedData(t *testing.T) {
	w, _ := mustNewTestCrypto(t)
	sealedYAML, err := w.EncryptYAML(t.Context(), SecretYAML("my-secret", "default", map[string]string{
		"username": "admin",
		"password": "hunter2",
	}, ""), "default", "my-secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}
	sealed, err := parseSealedSecret(sealedYAML)
	if err != nil {
		t.Fatalf("parseSealedSecret: %v", err)
	}
	sealed.Spec.EncryptedData["unrelated"] = "not-base64"
	sealedYAML, err = encodeSealedSecret(sealed, w.codecs)
	if err != nil {
		t.Fatalf("encodeSealedSecret: %v", err)
	}

	got, err := w.DecryptKey(t.Context(), sealedYAML, "password")
	if err != nil {
		t.Fatalf("DecryptKey: %v", err)
	}
	if got != "hunter2" {
		t.Fatalf("DecryptKey = %q, want %q", got, "hunter2")
	}

	if _, err := w.DecryptKey(t.Context(), sealedYAML, "missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("DecryptKey missing key error = %v, want ErrKeyNotFound", err)
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

// rotatingPrivProvider serves a stale list until it is invalidated, which is what a key that rotated
// inside the provider's cache window looks like from here.
type rotatingPrivProvider struct {
	current     []*rsa.PrivateKey
	fresh       []*rsa.PrivateKey
	calls       int
	invalidated int
}

func (p *rotatingPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	p.calls++
	return p.current, nil
}

func (p *rotatingPrivProvider) InvalidateKeyCache() {
	p.invalidated++
	p.current = p.fresh
}

// plainPrivProvider implements only PrivateKeyProvider, which is what a provider that does not cache
// looks like: the invalidation is an optional capability, so the retry must be skipped rather than
// assumed.
type plainPrivProvider struct {
	keys  []*rsa.PrivateKey
	calls int
}

func (p *plainPrivProvider) PrivateKeys(_ context.Context) ([]*rsa.PrivateKey, error) {
	p.calls++
	return p.keys, nil
}

// TestDecryptRetriesAfterInvalidatingAStaleKeyList covers the condition that makes caching the
// controller key list acceptable. A key that rotated after the provider built its list is missing
// from it, which arrives as an unseal failure; without the retry that is a Secret that cannot be
// revealed at all until the cache happens to expire.
func TestDecryptRetriesAfterInvalidatingAStaleKeyList(t *testing.T) {
	sealer, oldKey := mustNewTestCrypto(t)
	_, newKey := mustNewTestCrypto(t)

	sealed, err := sealer.EncryptYAML(t.Context(),
		SecretYAML("secret", "default", map[string]string{"key": "val"}, ""),
		"default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	provider := &rotatingPrivProvider{
		current: []*rsa.PrivateKey{newKey},         // the stale list: the rotated-in key only
		fresh:   []*rsa.PrivateKey{newKey, oldKey}, // what a fresh read returns
	}
	decrypted, err := New(sealer.cert, provider).DecryptYAML(t.Context(), sealed)
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}
	if !strings.Contains(decrypted, "key: val") {
		t.Fatalf("decrypted output missing value: %s", decrypted)
	}
	if provider.invalidated != 1 {
		t.Fatalf("invalidation calls = %d, want 1", provider.invalidated)
	}
	if provider.calls != 2 {
		t.Fatalf("key list calls = %d, want 2 (the failing attempt and the retry)", provider.calls)
	}
}

// TestDecryptDoesNotRetryWithoutACache is the other half: a provider with nothing to drop must not be
// asked to, so an operation that genuinely failed stays one key fetch rather than two.
func TestDecryptDoesNotRetryWithoutACache(t *testing.T) {
	sealer, _ := mustNewTestCrypto(t)
	_, otherKey := mustNewTestCrypto(t)

	sealed, err := sealer.EncryptYAML(t.Context(),
		SecretYAML("secret", "default", map[string]string{"key": "val"}, ""),
		"default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	provider := &plainPrivProvider{keys: []*rsa.PrivateKey{otherKey}}
	if _, err := New(sealer.cert, provider).DecryptYAML(t.Context(), sealed); err == nil {
		t.Fatal("expected decryption with only an unrelated key to fail, got nil")
	}
	if provider.calls != 1 {
		t.Fatalf("key list calls = %d, want 1", provider.calls)
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

// TestSealMutationsNeedsNoPrivateKey pins the blind path: a wrapper built without a private-key
// provider can still add, replace, and delete entries, because only the certificate is used.
func TestSealMutationsNeedsNoPrivateKey(t *testing.T) {
	sealer, _ := mustNewTestCrypto(t)
	sealed, err := sealer.EncryptYAML(t.Context(), SecretYAML("secret", "default", map[string]string{
		"existing": "old-value",
	}, ""), "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	blind := New(sealer.cert, nil)
	out, err := blind.SealMutations(t.Context(), sealed, []Mutation{
		{Key: "added", Value: "new-value", Op: ResealAdd},
	})
	if err != nil {
		t.Fatalf("SealMutations: %v", err)
	}

	decrypted, err := sealer.DecryptYAML(t.Context(), out)
	if err != nil {
		t.Fatalf("DecryptYAML after blind edit: %v", err)
	}
	if !strings.Contains(decrypted, "existing: old-value") {
		t.Errorf("existing key should be preserved: %s", decrypted)
	}
	if !strings.Contains(decrypted, "added: new-value") {
		t.Errorf("added key should be present: %s", decrypted)
	}
}

// TestSealMutationsCarriesEveryUntouchedEntryByteForByte is what makes the blind path safe: only the
// entries named by the batch change, so a caller who cannot decrypt still cannot corrupt the rest.
func TestSealMutationsCarriesEveryUntouchedEntryByteForByte(t *testing.T) {
	w, _ := mustNewTestCrypto(t)
	sealed, err := w.EncryptYAML(t.Context(), SecretYAML("secret", "default", map[string]string{
		"keep":   "keep-value",
		"change": "old-value",
		"remove": "remove-value",
	}, ""), "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}
	before, err := parseSealedSecret(sealed)
	if err != nil {
		t.Fatalf("parse before: %v", err)
	}

	out, err := w.SealMutations(t.Context(), sealed, []Mutation{
		{Key: "change", Value: "new-value", Op: ResealReplace},
		{Key: "remove", Op: ResealDelete},
		{Key: "added", Value: "added-value", Op: ResealAdd},
	})
	if err != nil {
		t.Fatalf("SealMutations: %v", err)
	}
	after, err := parseSealedSecret(out)
	if err != nil {
		t.Fatalf("parse after: %v", err)
	}

	if after.Spec.EncryptedData["keep"] != before.Spec.EncryptedData["keep"] {
		t.Error("an entry the batch did not name must not be resealed")
	}
	if after.Spec.EncryptedData["change"] == before.Spec.EncryptedData["change"] {
		t.Error("a replaced entry must carry new ciphertext")
	}
	if _, ok := after.Spec.EncryptedData["remove"]; ok {
		t.Error("a deleted entry must be gone")
	}
	if _, ok := after.Spec.EncryptedData["added"]; !ok {
		t.Error("an added entry must be present")
	}
}

// TestSealMutationsKeepsTheSealingScope proves the new entries were sealed under the object's own
// scope: a strict label mismatched with the annotations would fail to unseal.
func TestSealMutationsKeepsTheSealingScope(t *testing.T) {
	w, _ := mustNewTestCrypto(t)
	sealed, err := w.EncryptYAML(t.Context(), SecretYAML("secret", "default", map[string]string{
		"existing": "old-value",
	}, ""), "default", "secret", NamespaceWideScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}
	before, err := parseSealedSecret(sealed)
	if err != nil {
		t.Fatalf("parse before: %v", err)
	}

	out, err := w.SealMutations(t.Context(), sealed, []Mutation{{Key: "added", Value: "new-value", Op: ResealAdd}})
	if err != nil {
		t.Fatalf("SealMutations: %v", err)
	}
	after, err := parseSealedSecret(out)
	if err != nil {
		t.Fatalf("parse after: %v", err)
	}
	for key, want := range before.Annotations {
		if after.Annotations[key] != want {
			t.Errorf("annotation %q changed from %q to %q", key, want, after.Annotations[key])
		}
	}
	decrypted, err := w.DecryptYAML(t.Context(), out)
	if err != nil {
		t.Fatalf("DecryptYAML after blind edit: %v", err)
	}
	if !strings.Contains(decrypted, "added: new-value") {
		t.Errorf("added key did not survive a namespace-wide unseal: %s", decrypted)
	}
}

// TestSealMutationsRefusesTheLegacyDataBlob: spec.data is one opaque pre-v0.11 blob, so it cannot be
// edited key by key without decrypting all of it.
func TestSealMutationsRefusesTheLegacyDataBlob(t *testing.T) {
	w, _ := mustNewTestCrypto(t)
	const legacy = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: secret
  namespace: default
spec:
  data: AgAAAA==
  encryptedData: {}
`
	_, err := w.SealMutations(t.Context(), legacy, []Mutation{{Key: "added", Value: "v", Op: ResealAdd}})
	if !errors.Is(err, ErrInvalidMutation) {
		t.Fatalf("error = %v, want ErrInvalidMutation", err)
	}
}

// TestResealManyDeletesTheOnlyKeyWhileAddingAnother pins that deleting the only key is allowed when
// the same batch adds another: the Secret nets to one key, so it is never empty. The "cannot delete
// the final key" rule must look at the net of the whole batch, not refuse the delete because it
// sorts ahead of the add in the client's array. Regression for a 400 the editor hit on exactly this
// edit — delete the one key, add a replacement.
func TestResealManyDeletesTheOnlyKeyWhileAddingAnother(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{"key": "old"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	// Delete sent before the add, which is the order the editor stages existing-key changes ahead of
	// new rows.
	resealed, err := w.ResealMany(t.Context(), sealed, []Mutation{
		{Key: "key", Op: ResealDelete},
		{Key: "ff", Value: "new", Op: ResealAdd},
	})
	if err != nil {
		t.Fatalf("ResealMany delete-and-add should be allowed: %v", err)
	}

	decrypted, err := w.DecryptYAML(t.Context(), resealed)
	if err != nil {
		t.Fatalf("DecryptYAML after ResealMany: %v", err)
	}
	if strings.Contains(decrypted, "key:") {
		t.Errorf("deleted key should not appear: %s", decrypted)
	}
	if !strings.Contains(decrypted, "ff: new") {
		t.Errorf("added key should be present: %s", decrypted)
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
		{"add a key with a space", []Mutation{{Key: "my key", Value: "a", Op: ResealAdd}}},
		{"replace onto a key with a leading dash", []Mutation{{Key: "-lead", Value: "a", Op: ResealReplace}}},
		{"unknown operation", []Mutation{{Key: "one", Value: "a", Op: ResealOp("merge")}}},
	}
	for _, tc := range cases {
		if _, err := w.ResealMany(t.Context(), sealed, tc.mutations); err == nil {
			t.Errorf("%s: expected an error, got nil", tc.name)
		}
	}
}

// A Secret sealed before key-name validation may carry a key the rule now refuses; removing
// that key must stay possible, so the delete op is exempt from the check.
func TestResealManyAllowsDeletingAnInvalidKeyName(t *testing.T) {
	w, _ := mustNewTestCrypto(t)

	secretYAML := SecretYAML("secret", "default", map[string]string{"bad key": "v", "good": "v"}, "")
	sealed, err := w.EncryptYAML(t.Context(), secretYAML, "default", "secret", StrictScope)
	if err != nil {
		t.Fatalf("EncryptYAML: %v", err)
	}

	out, err := w.ResealMany(t.Context(), sealed, []Mutation{{Key: "bad key", Op: ResealDelete}})
	if err != nil {
		t.Fatalf("ResealMany delete of an invalid key name: %v", err)
	}
	keys, err := w.ExtractKeys(out)
	if err != nil {
		t.Fatalf("ExtractKeys: %v", err)
	}
	if len(keys) != 1 || keys[0] != "good" {
		t.Errorf("expected only 'good' left, got %v", keys)
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
