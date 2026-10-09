package middleware

import (
	"testing"
)

// An identity's effective grant in a namespace is its global set unioned with
// that namespace's own grants. Testing only the scoped list would drop a '*'
// grant the moment a user also had one namespace scoped to them.
func TestCapabilitiesForUnionsGlobalAndScoped(t *testing.T) {
	identity := Identity{
		Capabilities: []string{"metadata:read"},
		NamespaceCapabilities: map[string][]string{
			"payments": {"secret:seal"},
		},
	}

	payments := identity.CapabilitiesFor("payments")
	for _, want := range []string{"metadata:read", "secret:seal"} {
		if !containsCapability(payments, want) {
			t.Errorf("payments = %v, want %s", payments, want)
		}
	}
	if len(payments) != 2 {
		t.Errorf("payments = %v, want exactly the union", payments)
	}

	// A namespace with no grants of its own still has the global set: absent
	// from the map is not the same as denied.
	if got := identity.CapabilitiesFor("development"); len(got) != 1 || got[0] != "metadata:read" {
		t.Errorf("development = %v, want the global set", got)
	}
}

func TestHasCapabilityIn(t *testing.T) {
	identity := Identity{
		Capabilities:          []string{"metadata:read"},
		NamespaceCapabilities: map[string][]string{"payments": {"secret:seal"}},
	}
	cases := []struct {
		namespace  string
		capability string
		want       bool
	}{
		{"payments", "secret:seal", true},
		{"payments", "metadata:read", true}, // the global grant reaches here too
		{"development", "metadata:read", true},
		{"development", "secret:seal", false}, // scoped elsewhere
		{"", "secret:seal", false},            // an unnamed namespace is not a wildcard
	}
	for _, tc := range cases {
		if got := identity.HasCapabilityIn(tc.namespace, tc.capability); got != tc.want {
			t.Errorf("HasCapabilityIn(%q, %q) = %t, want %t", tc.namespace, tc.capability, got, tc.want)
		}
	}
}

func TestHasCapabilityAnywhere(t *testing.T) {
	identity := Identity{
		NamespaceCapabilities: map[string][]string{"payments": {"secret:seal"}},
	}
	if !identity.HasCapabilityAnywhere("secret:seal") {
		t.Error("a scoped grant should be visible to the pre-filter")
	}
	if identity.HasCapabilityAnywhere("secret:decrypt") {
		t.Error("a capability nobody grants was reported as held")
	}

	var none Identity
	if none.HasCapabilityAnywhere("metadata:read") {
		t.Error("an identity with no grants reports holding one")
	}
}

// Nil in, nil out: an identity with no grants should not carry an allocated
// empty slice through every request.
func TestCapabilitiesForWithNoGrants(t *testing.T) {
	var identity Identity
	if got := identity.CapabilitiesFor("payments"); got != nil {
		t.Errorf("CapabilitiesFor = %v, want nil", got)
	}
}
