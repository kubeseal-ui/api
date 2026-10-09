package policy

import (
	"testing"
)

// applyDoc is the shortest way to get a store into a known state: a document
// via Apply, which is exactly what a mounted ConfigMap does.
func applyDoc(t *testing.T, doc string) *PolicyStore {
	t.Helper()
	parsed, err := ParseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	store := NewPolicyStore()
	if err := store.Apply(parsed); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return store
}

func has(caps []Capability, want Capability) bool {
	for _, cap := range caps {
		if cap == want {
			return true
		}
	}
	return false
}

func TestGlobalGrantAppliesInEveryNamespace(t *testing.T) {
	store := applyDoc(t, `
version: 1
authz:
  groups:
    - name: platform-admins
      namespaces: ['*']
      role: release-pusher
`)
	global, scoped := store.NamespaceGrants([]string{"platform-admins"})
	if !has(global, GitOpsPush) || !has(global, MetadataRead) {
		t.Fatalf("global = %v, want release-pusher's bundle", global)
	}
	if len(scoped) != 0 {
		t.Fatalf("scoped = %v, want none", scoped)
	}
}

func TestScopedGrantAppliesOnlyWhereItNames(t *testing.T) {
	store := applyDoc(t, `
version: 1
authz:
  roles:
    payments-sealer:
      capabilities: [metadata:read, secret:seal]
  groups:
    - name: payments-team
      namespaces: [payments]
      role: payments-sealer
`)
	global, scoped := store.NamespaceGrants([]string{"payments-team"})
	if len(global) != 0 {
		t.Fatalf("global = %v, want none", global)
	}
	if !has(scoped["payments"], SecretSeal) {
		t.Fatalf("scoped = %v, want secret:seal in payments", scoped)
	}
	if _, ok := scoped["development"]; ok {
		t.Fatal("a namespace the rule does not name received a grant")
	}

	// CapabilitiesForGroups answers "somewhere", which is what a pre-filter
	// needs — it must not be read as a per-namespace answer.
	if !has(store.CapabilitiesForGroups([]string{"payments-team"}), SecretSeal) {
		t.Fatal("CapabilitiesForGroups lost a scoped grant")
	}
}

func TestGrantsUnionAcrossRules(t *testing.T) {
	store := applyDoc(t, `
version: 1
authz:
  groups:
    - name: platform-admins
      namespaces: ['*']
      role: viewer
    - name: platform-admins
      namespaces: [payments]
      role: secret-manager
    - name: payments-team
      namespaces: [payments]
      role: release-pusher
`)
	global, scoped := store.NamespaceGrants([]string{"platform-admins", "payments-team"})
	if !has(global, MetadataRead) {
		t.Fatalf("global = %v, want metadata:read", global)
	}
	if has(global, SecretDecrypt) {
		t.Fatalf("global = %v, must not carry a scoped grant", global)
	}
	payments := scoped["payments"]
	for _, want := range []Capability{SecretDecrypt, GitOpsPush} {
		if !has(payments, want) {
			t.Errorf("payments = %v, want %s", payments, want)
		}
	}
}

func TestNoMatchingRuleGrantsNothing(t *testing.T) {
	store := applyDoc(t, `
version: 1
authz:
  groups:
    - name: payments-team
      namespaces: [payments]
      role: secret-manager
`)
	global, scoped := store.NamespaceGrants([]string{"strangers"})
	if len(global) != 0 || len(scoped) != 0 {
		t.Fatalf("a group in no rule got %v / %v", global, scoped)
	}
}

// The fallback is what a deployment with no policy file runs on. Once a file is
// read, the file is the policy: a group that happens to be named after a role
// must stop granting anything, or a grant could never be revoked.
func TestApplyTurnsOffTheGroupNameFallback(t *testing.T) {
	store := NewPolicyStore()
	if !has(store.CapabilitiesForGroups([]string{"secret-manager"}), SecretDecrypt) {
		t.Fatal("without a document, a group named after a role should grant that role")
	}

	lockedDown := applyDoc(t, `
version: 1
authz:
  groups:
    - name: payments-team
      namespaces: [payments]
      role: secret-manager
`)
	if got := lockedDown.CapabilitiesForGroups([]string{"secret-manager"}); len(got) != 0 {
		t.Fatalf("fallback still granted %v after a document was applied", got)
	}
}

// SetGroupRoles is the programmatic path tests and setup code use. With no
// namespaces to scope it, it can only mean everywhere.
func TestSetGroupRolesGrantsEverywhere(t *testing.T) {
	store := NewPolicyStore()
	if err := store.SetGroupRoles("team", []string{"editor"}); err != nil {
		t.Fatal(err)
	}
	global, scoped := store.NamespaceGrants([]string{"team"})
	if !has(global, SecretSeal) || len(scoped) != 0 {
		t.Fatalf("global = %v, scoped = %v; want editor everywhere", global, scoped)
	}
}

// Apply replaces the group rules wholesale, which is what makes a reload able
// to revoke: a rule left out of the new document is gone.
func TestApplyReplacesRulesAndRoles(t *testing.T) {
	store := applyDoc(t, `
version: 1
authz:
  roles:
    payments-sealer:
      capabilities: [metadata:read, secret:seal]
  groups:
    - name: payments-team
      namespaces: [payments]
      role: payments-sealer
`)
	if !has(store.CapabilitiesForGroups([]string{"payments-team"}), SecretSeal) {
		t.Fatal("initial grant missing")
	}

	next, err := ParseDocument([]byte("version: 1\nauthz: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(next); err != nil {
		t.Fatal(err)
	}
	if got := store.CapabilitiesForGroups([]string{"payments-team"}); len(got) != 0 {
		t.Fatalf("capabilities = %v after the role was removed", got)
	}
	if _, ok := store.GetRole("payments-sealer"); ok {
		t.Error("a custom role outlived the document that declared it")
	}
}

// An applied document must leave Git mappings alone: they come from
// GITOPS_NAMESPACES, and a policy reload that dropped them would take delivery
// down as a side effect of editing authorization.
func TestApplyLeavesGitMappingsUntouched(t *testing.T) {
	store := applyDoc(t, "version: 1\nauthz: {}\n")
	if err := store.SetGitMapping(validMapping("payments")); err != nil {
		t.Fatal(err)
	}
	next, err := ParseDocument([]byte("version: 1\nauthz: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(next); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.GetGitMapping("payments"); !ok {
		t.Error("Apply dropped a Git mapping")
	}
}
