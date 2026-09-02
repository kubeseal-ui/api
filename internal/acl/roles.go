package acl

// Built-in roles. Capability sets follow the kubeseal-gui design:
//
//	viewer          — read metadata only
//	editor          — read + seal
//	secret-manager  — editor + decrypt (can decrypt but not manage ACLs)
//	platform-admin  — read + seal + access management; NO implicit
//	                  decrypt (must be granted explicitly)
//
// platform-admin deliberately omits SecretDecrypt: platform admins
// manage access but are not automatically trusted with plaintext.
var (
	RoleViewer = staticRole{name: "viewer", caps: []Capability{MetadataRead}}
	RoleEditor = staticRole{
		name: "editor",
		caps: []Capability{MetadataRead, SecretSeal},
	}
	RoleSecretManager = staticRole{
		name: "secret-manager",
		caps: []Capability{MetadataRead, SecretSeal, SecretDecrypt},
	}
	RolePlatformAdmin = staticRole{
		name: "platform-admin",
		caps: []Capability{MetadataRead, SecretSeal, AccessManage},
	}
)

// NewCustomRole builds a Role from an explicit capability list.
// Unknown capabilities are rejected so a typo in an ACL mapping
// fails at load time, not at authorization time.
func NewCustomRole(name string, caps []Capability) (Role, error) {
	seen := map[Capability]bool{}
	for _, c := range caps {
		if !c.Valid() {
			return nil, &UnknownCapabilityError{Capability: c, Role: name}
		}
		seen[c] = true
	}
	uniq := make([]Capability, 0, len(seen))
	for _, c := range All {
		if seen[c] {
			uniq = append(uniq, c)
		}
	}
	return staticRole{name: name, caps: uniq}, nil
}

// UnknownCapabilityError reports an invalid capability in a role.
type UnknownCapabilityError struct {
	Capability Capability
	Role       string
}

// Error implements error.
func (e *UnknownCapabilityError) Error() string {
	return "acl: role " + e.Role + " references unknown capability " + string(e.Capability)
}
