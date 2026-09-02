package acl

import "testing"

// TestMockIdentitiesHaveExpectedCapabilities pins the full capability
// matrix from phase-1.md.
func TestMockIdentitiesHaveExpectedCapabilities(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want []Capability
	}{
		{"viewer", MockViewer, []Capability{MetadataRead}},
		{"editor", MockEditor, []Capability{MetadataRead, SecretSeal}},
		{
			"secret-manager",
			MockSecretManager,
			[]Capability{MetadataRead, SecretSeal, SecretDecrypt},
		},
		{
			"platform-admin",
			MockPlatformAdmin,
			[]Capability{MetadataRead, SecretSeal, AccessManage},
		},
		{"denied", MockDenied, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.id.Capabilities()
			if len(got) != len(tc.want) {
				t.Fatalf("got %d capabilities %v, want %v", len(got), got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("caps[%d] = %q, want %q", i, got[i], tc.want[i])
				}
				if !tc.id.Has(tc.want[i]) {
					t.Errorf("Has(%q) = false, want true", tc.want[i])
				}
			}
		})
	}
}

// TestDenyByDefault verifies an identity with no roles holds nothing.
func TestDenyByDefault(t *testing.T) {
	for _, c := range All {
		if MockDenied.Has(c) {
			t.Errorf("denied identity unexpectedly holds %q", c)
		}
	}
	if MockDenied.ID() != "denied@example.test" {
		t.Errorf("unexpected denied id %q", MockDenied.ID())
	}
}

// TestPlatformAdminHasNoImplicitDecrypt verifies the security
// property that platform admins are not implicitly trusted with
// plaintext.
func TestPlatformAdminHasNoImplicitDecrypt(t *testing.T) {
	if MockPlatformAdmin.Has(SecretDecrypt) {
		t.Fatal("platform-admin must NOT implicitly hold secret:decrypt")
	}
}

// TestMultiGroupCapabilitiesAreAdditiveUnion verifies that multiple
// group memberships union their capabilities.
func TestMultiGroupCapabilitiesAreAdditiveUnion(t *testing.T) {
	got := MockMultiGroup.Capabilities()
	want := []Capability{MetadataRead, SecretSeal, SecretDecrypt}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("caps[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	groups := MockMultiGroup.Groups()
	if len(groups) != 2 {
		t.Errorf("want 2 groups, got %v", groups)
	}
}

// TestCustomRoleValidates verifies custom role construction and
// rejection of unknown capabilities.
func TestCustomRoleValidates(t *testing.T) {
	r, err := NewCustomRole("custom-role", []Capability{MetadataRead, GitOpsPush})
	if err != nil {
		t.Fatalf("NewCustomRole: %v", err)
	}
	if r.Name() != "custom-role" {
		t.Errorf("name = %q", r.Name())
	}
	if len(r.Capabilities()) != 2 {
		t.Errorf("caps = %v", r.Capabilities())
	}

	if _, err := NewCustomRole("bad-role", []Capability{Capability("no:such:cap")}); err == nil {
		t.Fatal("want error for unknown capability")
	}
}
