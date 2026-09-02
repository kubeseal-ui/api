// Package acl defines the capability model for the kubeseal-ui api.
//
// Phase 1 ships the interfaces plus deterministic mock identities so
// handlers and tests can exercise authorization decisions without a
// live OpenFGA server. Production enforcement (OpenFGA, team-based
// usersets) lands in Phase 2 per internal-docs/engineering/backend/.
//
// Capability names follow the kubeseal-gui design:
//
//	metadata:read   — list namespaces and SealedSecret metadata
//	secret:seal     — encrypt / create SealedSecrets
//	secret:decrypt  — decrypt (requires reader on the resource in
//	                  the full model; here a plain capability)
//	gitops:push     — deliver sealed YAML to the configuration repo
//	access:manage   — manage ACL mappings (platform admins)
package acl

// Capability is a named permission. The set of capabilities is
// closed and documented; unknown strings are rejected at parse time.
type Capability string

// Known capabilities.
const (
	MetadataRead  Capability = "metadata:read"
	SecretSeal    Capability = "secret:seal"
	SecretDecrypt Capability = "secret:decrypt"
	GitOpsPush    Capability = "gitops:push"
	AccessManage  Capability = "access:manage"
)

// All lists every capability for validation and role assembly.
var All = []Capability{
	MetadataRead,
	SecretSeal,
	SecretDecrypt,
	GitOpsPush,
	AccessManage,
}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	for _, known := range All {
		if c == known {
			return true
		}
	}
	return false
}

// Identity is an authenticated principal. Phase 1 identities are
// mocks; Phase 2 replaces them with OIDC-derived identities carrying
// team memberships.
type Identity interface {
	// ID is the stable subject identifier (email or sub claim).
	ID() string
	// Groups are the team/group memberships of the identity.
	Groups() []string
	// Has reports whether the identity holds a capability.
	Has(c Capability) bool
	// Capabilities returns the full capability set of the identity.
	Capabilities() []Capability
}

// Role is a named bundle of capabilities. Roles are the unit of
// ACL mapping: a group maps to a role, an identity in multiple
// groups gets the union of those roles' capabilities.
type Role interface {
	// Name is the role identifier.
	Name() string
	// Capabilities returns the role's capability set.
	Capabilities() []Capability
}

// staticRole is a fixed capability bundle.
type staticRole struct {
	name string
	caps []Capability
}

// Name implements Role.
func (r staticRole) Name() string { return r.name }

// Capabilities implements Role.
func (r staticRole) Capabilities() []Capability { return r.caps }
