package acl

// Mock identities for phase-1 testing. Deterministic: same inputs,
// same identities, every run. These mirror the capability matrix in
// internal-docs/implementation/phase-1.md.
var (
	// MockViewer can read metadata only.
	MockViewer = mustIdentity("viewer@example.test", []string{"viewers"}, RoleViewer)

	// MockEditor can read metadata and seal.
	MockEditor = mustIdentity("editor@example.test", []string{"editors"}, RoleEditor)

	// MockSecretManager can read, seal, and decrypt.
	MockSecretManager = mustIdentity("secret-manager@example.test", []string{"secret-managers"}, RoleSecretManager)

	// MockPlatformAdmin can read, seal, and manage access — but has
	// NO implicit decrypt capability.
	MockPlatformAdmin = mustIdentity("platform-admin@example.test", []string{"platform-admins"}, RolePlatformAdmin)

	// MockMultiGroup is in two groups whose roles union additively.
	MockMultiGroup = mustIdentity("multi@example.test", []string{"viewers", "secret-managers"}, RoleViewer, RoleSecretManager)

	// MockDenied has no groups and no capabilities.
	MockDenied = mustIdentity("denied@example.test", nil)
)

// mustIdentity panics on invalid role combinations — a programming
// error in the test fixtures, not a runtime condition.
func mustIdentity(id string, groups []string, roles ...Role) Identity {
	ident, err := IdentityFromRoles(id, groups, roles...)
	if err != nil {
		panic(err)
	}
	return ident
}
