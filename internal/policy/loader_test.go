package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicy(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const loaderDocument = `
version: 1
authz:
  roles:
    payments-sealer:
      capabilities: [metadata:read, secret:seal]
  groups:
    - name: payments-team
      namespaces: [payments]
      role: payments-sealer
`

func TestNewLoaderAppliesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.yaml")
	writePolicy(t, path, loaderDocument)

	store := NewPolicyStore()
	loader, err := NewLoader(path, store)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if loader.Err() != nil {
		t.Fatalf("Err = %v after a successful load", loader.Err())
	}
	if loader.Path() != path {
		t.Errorf("Path = %q, want %q", loader.Path(), path)
	}
	if !has(store.CapabilitiesForGroups([]string{"payments-team"}), SecretSeal) {
		t.Fatal("the file's grant did not reach the store")
	}
}

// At boot there is no previous generation, so a broken or missing file is an error rather
// than a warning: the alternative is serving a policy the operator did not write.
func TestNewLoaderFailsOnAnUnusableFile(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"bad-version.yaml": "version: 2\nauthz: {}\n",
		"not-yaml.yaml":    "authz: [this is not a mapping\n",
		"unknown.yaml":     "version: 1\nauthz:\n  nope: true\n",
	} {
		path := filepath.Join(dir, name)
		writePolicy(t, path, content)
		if _, err := NewLoader(path, NewPolicyStore()); err == nil {
			t.Errorf("%s: NewLoader accepted an unusable document", name)
		}
	}
	if _, err := NewLoader(filepath.Join(dir, "absent.yaml"), NewPolicyStore()); err == nil {
		t.Error("NewLoader accepted a missing file")
	}
}

func TestReloadPicksUpAnEdit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.yaml")
	writePolicy(t, path, "version: 1\nauthz: {}\n")
	store := NewPolicyStore()
	loader, err := NewLoader(path, store)
	if err != nil {
		t.Fatal(err)
	}

	writePolicy(t, path, loaderDocument)
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !has(store.CapabilitiesForGroups([]string{"payments-team"}), SecretSeal) {
		t.Fatal("the reload did not take effect")
	}
}

// A failed reload keeps the last valid generation in force: falling back to no policy would
// turn a file being edited into a lockout at the worst possible moment.
func TestFailedReloadKeepsTheLastValidGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.yaml")
	writePolicy(t, path, loaderDocument)
	store := NewPolicyStore()
	loader, err := NewLoader(path, store)
	if err != nil {
		t.Fatal(err)
	}

	writePolicy(t, path, "version: 9\nauthz: {}\n")
	if err := loader.Reload(); err == nil {
		t.Fatal("Reload accepted an unsupported version")
	}
	if loader.Err() == nil {
		t.Fatal("Err is nil after a failed reload; readiness would not notice")
	}
	if !has(store.CapabilitiesForGroups([]string{"payments-team"}), SecretSeal) {
		t.Fatal("a failed reload discarded the generation it could not replace")
	}

	// A later good reload clears the failure, or the process would stay unready forever
	// after one bad edit.
	writePolicy(t, path, loaderDocument)
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload after the fix: %v", err)
	}
	if loader.Err() != nil {
		t.Fatalf("Err = %v after a successful reload", loader.Err())
	}
}

// Removing a grant from the file removes it from the store — the property an additive design
// could not have.
func TestReloadRevokesARemovedGrant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.yaml")
	writePolicy(t, path, loaderDocument)
	store := NewPolicyStore()
	loader, err := NewLoader(path, store)
	if err != nil {
		t.Fatal(err)
	}
	if !has(store.CapabilitiesForGroups([]string{"payments-team"}), SecretSeal) {
		t.Fatal("initial grant missing")
	}

	writePolicy(t, path, "version: 1\nauthz:\n  groups: []\n")
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := store.CapabilitiesForGroups([]string{"payments-team"}); len(got) != 0 {
		t.Fatalf("capabilities = %v after the grant was removed", got)
	}
}
