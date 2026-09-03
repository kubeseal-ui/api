// Package policy tests - RED-GREEN-REFACTOR per test-driven-development skill.
package policy

import (
	"strings"
	"testing"
)

// TestBuiltInRolesHaveExpectedCapabilities verifies built-in roles have correct capabilities.
func TestBuiltInRolesHaveExpectedCapabilities(t *testing.T) {
	tests := []struct {
		name         string
		role         Role
		expectedCaps []Capability
	}{
		{
			name:         "viewer",
			role:         RoleViewer,
			expectedCaps: []Capability{MetadataRead},
		},
		{
			name:         "editor",
			role:         RoleEditor,
			expectedCaps: []Capability{MetadataRead, SecretSeal},
		},
		{
			name:         "secret-manager",
			role:         RoleSecretManager,
			expectedCaps: []Capability{MetadataRead, SecretSeal, SecretDecrypt},
		},
		{
			name:         "platform-admin",
			role:         RolePlatformAdmin,
			expectedCaps: []Capability{MetadataRead, SecretSeal, AccessManage},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.role.Capabilities) != len(tc.expectedCaps) {
				t.Fatalf("%s: got %d capabilities, want %d", tc.name, len(tc.role.Capabilities), len(tc.expectedCaps))
			}
			for _, expected := range tc.expectedCaps {
				found := false
				for _, actual := range tc.role.Capabilities {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: missing capability %q", tc.name, expected)
				}
			}
		})
	}
}

// TestPlatformAdminHasNoImplicitDecrypt verifies platform-admin does not have secret:decrypt.
func TestPlatformAdminHasNoImplicitDecrypt(t *testing.T) {
	for _, cap := range RolePlatformAdmin.Capabilities {
		if cap == SecretDecrypt {
			t.Error("platform-admin should not have secret:decrypt capability")
		}
	}
}

// TestPlatformAdminHasNoImplicitGitPush verifies platform-admin does not have gitops:push.
func TestPlatformAdminHasNoImplicitGitPush(t *testing.T) {
	for _, cap := range RolePlatformAdmin.Capabilities {
		if cap == GitOpsPush {
			t.Error("platform-admin should not have gitops:push capability")
		}
		if cap == GitOpsPropose {
			t.Error("platform-admin should not have gitops:propose capability")
		}
	}
}

// TestCustomRoleValidatesUnknownCapabilityRejected verifies unknown capabilities are rejected.
func TestCustomRoleValidatesUnknownCapabilityRejected(t *testing.T) {
	_, err := NewCustomRole("custom-role", []Capability{MetadataRead, "unknown:cap"})
	if err == nil {
		t.Error("expected error for unknown capability")
	}
	if !strings.Contains(err.Error(), "unknown capability") {
		t.Errorf("expected 'unknown capability' error, got: %v", err)
	}
}

// TestCustomRoleValidatesBuiltInNameRejected verifies custom role can't use built-in name.
func TestCustomRoleValidatesBuiltInNameRejected(t *testing.T) {
	_, err := NewCustomRole("viewer", []Capability{MetadataRead})
	if err == nil {
		t.Error("expected error for built-in role name conflict")
	}
	if !strings.Contains(err.Error(), "conflicts with built-in role") {
		t.Errorf("expected 'conflicts with built-in role' error, got: %v", err)
	}
}

// TestIdentityCapabilitiesAreAdditiveUnion verifies identity gets union of role capabilities.
func TestIdentityCapabilitiesAreAdditiveUnion(t *testing.T) {
	identity := Identity{
		Subject: "user-123",
		Roles:   []string{"viewer", "editor"},
	}

	caps := identity.Capabilities()
	expected := []Capability{MetadataRead, SecretSeal}

	if len(caps) != len(expected) {
		t.Fatalf("got %d capabilities, want %d", len(caps), len(expected))
	}

	for _, expected := range expected {
		found := false
		for _, actual := range caps {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing capability %q", expected)
		}
	}
}

// TestDefaultDeny verifies identity with no roles has no capabilities.
func TestDefaultDeny(t *testing.T) {
	identity := Identity{
		Subject: "user-123",
		Roles:   []string{},
	}

	if identity.Has(MetadataRead) {
		t.Error("identity with no roles should not have metadata:read")
	}
	if identity.Has(SecretSeal) {
		t.Error("identity with no roles should not have secret:seal")
	}
	if identity.Has(SecretDecrypt) {
		t.Error("identity with no roles should not have secret:decrypt")
	}
	if identity.Has(GitOpsPush) {
		t.Error("identity with no roles should not have gitops:push")
	}
	if identity.Has(AccessManage) {
		t.Error("identity with no roles should not have access:manage")
	}
}

// TestIdentityHas reports whether Has works correctly.
func TestIdentityHas(t *testing.T) {
	identity := Identity{
		Subject: "user-123",
		Roles:   []string{"secret-manager"},
	}

	if !identity.Has(MetadataRead) {
		t.Error("secret-manager should have metadata:read")
	}
	if !identity.Has(SecretSeal) {
		t.Error("secret-manager should have secret:seal")
	}
	if !identity.Has(SecretDecrypt) {
		t.Error("secret-manager should have secret:decrypt")
	}
	if identity.Has(GitOpsPush) {
		t.Error("secret-manager should not have gitops:push")
	}
	if identity.Has(AccessManage) {
		t.Error("secret-manager should not have access:manage")
	}
}

// TestNamespaceGitMappingRequired verifies GitMapping requires all fields.
func TestNamespaceGitMappingRequired(t *testing.T) {
	tests := []struct {
		name        string
		mapping     GitMapping
		expectError bool
	}{
		{
			name: "valid mapping",
			mapping: GitMapping{
				Namespace:    "default",
				Repository:   "org/repo",
				Branch:       "main",
				PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
				AuthRef:      "git-credentials",
				Mode:         GitDeliveryDirect,
			},
			expectError: false,
		},
		{
			name: "missing namespace",
			mapping: GitMapping{
				Repository:   "org/repo",
				Branch:       "main",
				PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
				AuthRef:      "git-credentials",
				Mode:         GitDeliveryDirect,
			},
			expectError: true,
		},
		{
			name: "missing repository",
			mapping: GitMapping{
				Namespace:    "default",
				Branch:       "main",
				PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
				AuthRef:      "git-credentials",
				Mode:         GitDeliveryDirect,
			},
			expectError: true,
		},
		{
			name: "missing branch",
			mapping: GitMapping{
				Namespace:    "default",
				Repository:   "org/repo",
				PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
				AuthRef:      "git-credentials",
				Mode:         GitDeliveryDirect,
			},
			expectError: true,
		},
		{
			name: "missing path template",
			mapping: GitMapping{
				Namespace:  "default",
				Repository: "org/repo",
				Branch:     "main",
				Mode:       GitDeliveryDirect,
			},
			expectError: true,
		},
		{
			name: "invalid mode",
			mapping: GitMapping{
				Namespace:    "default",
				Repository:   "org/repo",
				Branch:       "main",
				PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
				Mode:         "invalid",
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mapping.Validate()
			if tc.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestNamespaceGitMappingFailsClosedOnAmbiguous is a placeholder for the actual check.
func TestNamespaceGitMappingFailsClosedOnAmbiguous(t *testing.T) {
	// This test documents that ambiguous mappings should fail closed.
	// The actual implementation would check for duplicate namespace mappings.
	t.Skip("Implementation depends on policy store enforcement")
}

// TestGitDeliveryModeDirectRequiresGitOpsPush verifies direct mode requires gitops:push.
func TestGitDeliveryModeDirectRequiresGitOpsPush(t *testing.T) {
	mapping := GitMapping{
		Namespace:    "default",
		Repository:   "org/repo",
		Branch:       "main",
		PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
		Mode:         GitDeliveryDirect,
	}

	cap := GitOpsCapabilityRequired(mapping.Mode)
	if cap != GitOpsPush {
		t.Errorf("direct mode should require gitops:push, got %q", cap)
	}
}

// TestGitDeliveryModeProposalRequiresGitOpsPropose verifies proposal mode requires gitops:propose.
func TestGitDeliveryModeProposalRequiresGitOpsPropose(t *testing.T) {
	mapping := GitMapping{
		Namespace:    "default",
		Repository:   "org/repo",
		Branch:       "main",
		PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
		Mode:         GitDeliveryProposal,
	}

	cap := GitOpsCapabilityRequired(mapping.Mode)
	if cap != GitOpsPropose {
		t.Errorf("proposal mode should require gitops:propose, got %q", cap)
	}
}

// TestPolicyStoreCustomRoleManagement tests custom role add/get.
func TestPolicyStoreCustomRoleManagement(t *testing.T) {
	store := NewPolicyStore()

	// Add custom role
	role, err := NewCustomRole("custom-editor", []Capability{MetadataRead, SecretSeal})
	if err != nil {
		t.Fatalf("NewCustomRole: %v", err)
	}

	if err := store.AddCustomRole(role); err != nil {
		t.Fatalf("AddCustomRole: %v", err)
	}

	// Get custom role
	got, ok := store.GetRole("custom-editor")
	if !ok {
		t.Fatal("custom role not found")
	}
	if got.Name != "custom-editor" {
		t.Errorf("role name mismatch: %q", got.Name)
	}

	// Try to add duplicate
	if err := store.AddCustomRole(role); err == nil {
		t.Error("expected error for duplicate custom role")
	}

	// Try to add with built-in name
	builtinRole := Role{Name: "viewer", Capabilities: []Capability{MetadataRead}}
	if err := store.AddCustomRole(builtinRole); err == nil {
		t.Error("expected error for built-in name conflict")
	}
}

// TestPolicyStoreGitMappingManagement tests Git mapping set/get.
func TestPolicyStoreGitMappingManagement(t *testing.T) {
	store := NewPolicyStore()

	mapping := GitMapping{
		Namespace:    "default",
		Repository:   "org/repo",
		Branch:       "main",
		PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
		AuthRef:      "git-credentials",
		Mode:         GitDeliveryDirect,
	}

	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatalf("SetGitMapping: %v", err)
	}

	got, ok := store.GetGitMapping("default")
	if !ok {
		t.Fatal("Git mapping not found")
	}
	if got.Repository != "org/repo" {
		t.Errorf("repository mismatch: %q", got.Repository)
	}

	// Non-existent namespace
	_, ok = store.GetGitMapping("nonexistent")
	if ok {
		t.Error("expected non-existent namespace to return false")
	}
}

// TestRequiredCapabilitiesForOperation verifies operation capability requirements.
func TestRequiredCapabilitiesForOperation(t *testing.T) {
	tests := []struct {
		operation    string
		expectedCaps []Capability
		shouldExist  bool
	}{
		{"list_namespaces", []Capability{MetadataRead}, true},
		{"get_sealedsecret", []Capability{MetadataRead}, true},
		{"list_sealedsecrets", []Capability{MetadataRead}, true},
		{"encrypt", []Capability{SecretSeal}, true},
		{"decrypt", []Capability{SecretDecrypt}, true},
		{"reseal", []Capability{SecretSeal, SecretDecrypt}, true},
		{"gitops_dry_run", []Capability{GitOpsPropose}, true},
		{"gitops_propose", []Capability{GitOpsPropose}, true},
		{"gitops_push", []Capability{GitOpsPush}, true},
		{"manage_acl", []Capability{AccessManage}, true},
		{"unknown_op", nil, false},
	}

	for _, tc := range tests {
		t.Run(tc.operation, func(t *testing.T) {
			caps := RequiredCapabilitiesForOperation(tc.operation)
			if tc.shouldExist {
				if caps == nil {
					t.Error("expected capabilities but got nil")
				}
				if len(caps) != len(tc.expectedCaps) {
					t.Errorf("expected %d capabilities, got %d", len(tc.expectedCaps), len(caps))
				}
			} else {
				if caps != nil {
					t.Errorf("expected nil for unknown operation, got %v", caps)
				}
			}
		})
	}
}

// TestCheckAuthorization verifies authorization checks work correctly.
func TestCheckAuthorization(t *testing.T) {
	editorIdentity := Identity{
		Subject: "user-123",
		Roles:   []string{"editor"},
	}

	secretManagerIdentity := Identity{
		Subject: "user-456",
		Roles:   []string{"secret-manager"},
	}

	viewerIdentity := Identity{
		Subject: "user-789",
		Roles:   []string{"viewer"},
	}

	tests := []struct {
		name        string
		identity    Identity
		operation   string
		expectError bool
	}{
		{"editor can encrypt", editorIdentity, "encrypt", false},
		{"editor cannot decrypt", editorIdentity, "decrypt", true},
		{"editor cannot reseal", editorIdentity, "reseal", true},
		{"secret-manager can decrypt", secretManagerIdentity, "decrypt", false},
		{"secret-manager can reseal", secretManagerIdentity, "reseal", false},
		{"viewer cannot encrypt", viewerIdentity, "encrypt", true},
		{"viewer can list namespaces", viewerIdentity, "list_namespaces", false},
		{"viewer cannot decrypt", viewerIdentity, "decrypt", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAuthorization(tc.identity, tc.operation)
			if tc.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestRenderPath verifies path template rendering.
func TestRenderPath(t *testing.T) {
	mapping := GitMapping{
		Namespace:    "default",
		Repository:   "org/repo",
		Branch:       "main",
		PathTemplate: "clusters/prod/{namespace}/{name}.yaml",
		Mode:         GitDeliveryDirect,
	}

	rendered := mapping.RenderPath("production", "db-cred")
	expected := "clusters/prod/production/db-cred.yaml"

	if rendered != expected {
		t.Errorf("RenderPath: got %q, want %q", rendered, expected)
	}
}

// TestCapabilityValid verifies capability validation.
func TestCapabilityValid(t *testing.T) {
	tests := []struct {
		cap           Capability
		shouldBeValid bool
	}{
		{MetadataRead, true},
		{SecretSeal, true},
		{SecretDecrypt, true},
		{GitOpsPropose, true},
		{GitOpsPush, true},
		{AccessManage, true},
		{"unknown:cap", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(string(tc.cap), func(t *testing.T) {
			if tc.cap.Valid() != tc.shouldBeValid {
				t.Errorf("Capability(%q).Valid() = %v, want %v", tc.cap, tc.cap.Valid(), tc.shouldBeValid)
			}
		})
	}
}
