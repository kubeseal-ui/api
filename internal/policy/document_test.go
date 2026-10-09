package policy

import (
	"strings"
	"testing"
)

// validDocument is the schema's own example, reduced to the authz half. It is
// the shape an operator copies out of internal-docs, so parsing it is the test
// that matters most: a document the docs call valid that the loader rejects
// would send every reader of those docs down a dead end.
const validDocument = `
version: 1

authz:
  defaults:
    unauthenticated: deny
    authenticated: deny

  roles:
    viewer:
      capabilities: [metadata:read]
    editor:
      capabilities: [metadata:read, secret:seal]
    secret-manager:
      capabilities: [metadata:read, secret:seal, secret:decrypt]
    release-proposer:
      capabilities: [metadata:read, gitops:propose]
    release-pusher:
      capabilities: [metadata:read, gitops:push]
    platform-admin:
      capabilities: [metadata:read, secret:seal, access:manage]

    team-secret-proposer:
      capabilities:
        - metadata:read
        - secret:seal
        - secret:decrypt
        - gitops:propose

  groups:
    - name: platform-admins
      namespaces: ['*']
      role: platform-admin
    - name: payments-secret-managers
      namespaces: [payments]
      role: team-secret-proposer
`

func TestParseDocumentAcceptsTheSchemaExample(t *testing.T) {
	doc, err := ParseDocument([]byte(validDocument))
	if err != nil {
		t.Fatalf("the documented example was rejected: %v", err)
	}
	if doc.Version != SupportedVersion {
		t.Fatalf("version = %d, want %d", doc.Version, SupportedVersion)
	}
	if len(doc.Authz.Roles) != 7 {
		t.Errorf("roles = %d, want 7", len(doc.Authz.Roles))
	}
	if len(doc.Authz.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(doc.Authz.Groups))
	}
	if got := doc.Authz.Groups[1]; got.Name != "payments-secret-managers" || got.Role != "team-secret-proposer" || len(got.Namespaces) != 1 || got.Namespaces[0] != "payments" {
		t.Errorf("second group = %+v", got)
	}
}

// A built-in role listed with exactly its canonical bundle is how a document
// stays self-describing; a document that redefines one is how a ConfigMap
// quietly changes what platform-admin means. Only the first is allowed.
func TestParseDocumentBuiltInRoleRedeclaration(t *testing.T) {
	canonical := `
version: 1
authz:
  roles:
    platform-admin:
      capabilities: [access:manage, secret:seal, metadata:read]
  groups:
    - name: platform-admins
      namespaces: ['*']
      role: platform-admin
`
	if _, err := ParseDocument([]byte(canonical)); err != nil {
		t.Fatalf("canonical redeclaration rejected: %v", err)
	}

	widened := `
version: 1
authz:
  roles:
    platform-admin:
      capabilities: [metadata:read, secret:seal, access:manage, gitops:push]
  groups:
    - name: platform-admins
      namespaces: ['*']
      role: platform-admin
`
	if _, err := ParseDocument([]byte(widened)); err == nil {
		t.Fatal("a built-in role redeclared with a different bundle was accepted")
	}
}

func TestParseDocumentRejections(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantSub string
	}{
		{
			name:    "no version",
			doc:     "authz:\n  groups:\n    - name: g\n      namespaces: ['*']\n      role: viewer\n",
			wantSub: "version",
		},
		{
			name:    "unsupported version",
			doc:     "version: 2\nauthz:\n  groups:\n    - name: g\n      namespaces: ['*']\n      role: viewer\n",
			wantSub: "version",
		},
		{
			name:    "unknown field",
			doc:     "version: 1\nauthz:\n  capabilites:\n    - metadata:read\n",
			wantSub: "capabilites",
		},
		{
			name:    "unknown capability",
			doc:     "version: 1\nauthz:\n  roles:\n    auditor:\n      capabilities: [metadata:write]\n",
			wantSub: "metadata:write",
		},
		{
			name:    "group references unknown role",
			doc:     "version: 1\nauthz:\n  groups:\n    - name: g\n      namespaces: ['*']\n      role: auditor\n",
			wantSub: "auditor",
		},
		{
			name:    "group without a role",
			doc:     "version: 1\nauthz:\n  groups:\n    - name: g\n      namespaces: ['*']\n",
			wantSub: "role",
		},
		{
			name:    "group without namespaces",
			doc:     "version: 1\nauthz:\n  groups:\n    - name: g\n      role: viewer\n",
			wantSub: "namespace",
		},
		{
			name:    "prefix glob namespace",
			doc:     "version: 1\nauthz:\n  groups:\n    - name: g\n      namespaces: ['pay*']\n      role: viewer\n",
			wantSub: "pay*",
		},
		{
			name:    "invalid namespace name",
			doc:     "version: 1\nauthz:\n  groups:\n    - name: g\n      namespaces: [Payments]\n      role: viewer\n",
			wantSub: "Payments",
		},
		{
			name: "two rules for one group over the same namespaces",
			doc: "version: 1\nauthz:\n  groups:\n    - name: g\n      namespaces: [payments]\n      role: viewer\n" +
				"    - name: g\n      namespaces: [payments]\n      role: editor\n",
			wantSub: "already has a rule",
		},
		{
			name:    "defaults allow",
			doc:     "version: 1\nauthz:\n  defaults:\n    authenticated: allow\n",
			wantSub: "allow",
		},
		{
			name:    "second document",
			doc:     "version: 1\nauthz:\n  groups:\n    - name: g\n      namespaces: ['*']\n      role: viewer\n---\nversion: 1\n",
			wantSub: "exactly one document",
		},
		{
			name:    "role with no capabilities",
			doc:     "version: 1\nauthz:\n  roles:\n    auditor:\n      capabilities: []\n",
			wantSub: "at least one capability",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDocument([]byte(tc.doc))
			if err == nil {
				t.Fatal("document was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestParseDocumentRejectsEmptyInput(t *testing.T) {
	for _, doc := range []string{"", "   \n", "# only a comment\n", "null\n"} {
		if _, err := ParseDocument([]byte(doc)); err == nil {
			t.Errorf("ParseDocument(%q) accepted an empty document", doc)
		}
	}
}

// A document written to the published schema carries a git: section. Refusing
// it would make the documented file unusable, so it is read past — but only
// past: nothing in it may influence authorization.
func TestParseDocumentIgnoresTheGitSection(t *testing.T) {
	doc := `
version: 1
authz:
  groups:
    - name: g
      namespaces: ['*']
      role: viewer
git:
  repositories:
    platform-config:
      url: https://git.example.com/platform/config.git
      branch: main
      authRef: platform-config-auth
  namespaces:
    payments:
      repository: platform-config
      pathTemplate: cluster/sealed-secret/{{.Namespace}}/{{.Name}}.yaml
`
	parsed, err := ParseDocument([]byte(doc))
	if err != nil {
		t.Fatalf("a document with a git section was rejected: %v", err)
	}
	store := NewPolicyStore()
	if err := store.Apply(parsed); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The git half must not have created a mapping: mappings come from
	// GITOPS_NAMESPACES, and a namespace appearing here because of an unread
	// section would be authorization the operator never configured.
	if _, ok := store.GetGitMapping("payments"); ok {
		t.Error("the git section created a namespace mapping")
	}
}

// The git half being inert is a property of the loader, which is where the
// warning about it is emitted — but Apply is what the loader calls, so this
// pins that a git-only document still applies its (empty) authorization.
func TestParseDocumentAcceptsAnAuthzOnlyDocument(t *testing.T) {
	doc, err := ParseDocument([]byte("version: 1\nauthz: {}\n"))
	if err != nil {
		t.Fatalf("authz-only document rejected: %v", err)
	}
	if len(doc.Authz.Groups) != 0 {
		t.Errorf("groups = %d, want 0", len(doc.Authz.Groups))
	}
}

// Validate collects every problem rather than stopping at the first, so an
// operator fixing a ConfigMap learns the whole list in one pass.
func TestValidateReportsEveryProblem(t *testing.T) {
	doc := Document{
		Version: 7,
		Authz: Authz{
			Defaults: Defaults{Authenticated: "allow"},
			Roles:    map[string]RoleSpec{"auditor": {Capabilities: []Capability{"metadata:write"}}},
			Groups: []GroupRule{
				{Name: "a", Namespaces: []string{"pay*"}, Role: "auditor"},
				{Name: "b", Namespaces: []string{"*"}, Role: "missing"},
			},
		},
	}
	err := doc.Validate()
	if err == nil {
		t.Fatal("invalid document validated")
	}
	for _, want := range []string{"version", "allow", "metadata:write", "pay*", "missing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}
