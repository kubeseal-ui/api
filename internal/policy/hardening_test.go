package policy

import (
	"context"
	"sync"
	"testing"

	"github.com/kubeseal-ui/api/internal/gitops"
)

type testProposalAdapter struct{}

func (testProposalAdapter) OpenProposal(context.Context, gitops.ProposalRequest) (gitops.ProposalResult, error) {
	return gitops.ProposalResult{}, nil
}

func validMapping(namespace string) GitMapping {
	return GitMapping{Namespace: namespace, Repository: "org/repo", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "git-auth", Mode: GitDeliveryDirect}
}

func TestGitMappingRejectsTraversalAndInvalidTemplate(t *testing.T) {
	cases := []GitMapping{
		func() GitMapping {
			m := validMapping("default")
			m.PathTemplate = "../{namespace}/{name}.yaml"
			return m
		}(),
		func() GitMapping {
			m := validMapping("default")
			m.PathTemplate = "clusters/{namespace}/{name}/{unknown}.yaml"
			return m
		}(),
		func() GitMapping {
			m := validMapping("default")
			m.PathTemplate = "clusters/{{.Namespace}}/{name}.yaml"
			return m
		}(),
	}
	for _, mapping := range cases {
		if err := mapping.Validate(); err == nil {
			t.Errorf("Validate(%q) accepted unsafe template", mapping.PathTemplate)
		}
	}
	mapping := validMapping("default")
	if got := mapping.RenderPath("../escape", "name"); got != "" {
		t.Fatalf("RenderPath traversal = %q", got)
	}
}

// TestIsPathAllowedRefusesNonCanonicalAndEscapingPaths pins the allowlist as a boundary on the path
// that is actually written, not on the string the client sent.
//
// An allowed prefix is matched by string, so `apps/dev/../ci/x.yaml` starts with `apps/dev/` and
// passes a naive test while the transport joins the raw path onto the worktree, where the filesystem
// cleans it for real and the write lands in `ci/`. A path that Clean would rewrite is therefore not
// judged at all.
func TestIsPathAllowedRefusesNonCanonicalAndEscapingPaths(t *testing.T) {
	mapping := validMapping("dev")
	mapping.AllowedPaths = []string{"apps/{namespace}"}

	allowed := []string{
		"apps/dev/x.yaml",
		"apps/dev/nested/x.yaml",
		"apps/dev/.hidden",
	}
	for _, path := range allowed {
		if !mapping.IsPathAllowed(path, "dev", "x") {
			t.Errorf("IsPathAllowed(%q) = false, want true", path)
		}
	}

	refused := []string{
		"apps/dev/../ci/release.yaml", // climbs out of the granted prefix
		"apps/dev/sub/../x.yaml",      // climbs within it, so the raw string still matches
		"apps/dev/./x.yaml",           // not canonical
		"apps//dev/x.yaml",            // not canonical
		"apps/dev",                    // the granted directory, not a file in it
		"apps/dev/",                   // ...nor with a trailing separator
		"apps/development/x.yaml",     // the prefix must end at a separator
		"/etc/passwd",                 // absolute
		"../apps/dev/x.yaml",          // above the checkout
		"",                            // no path at all
	}
	for _, path := range refused {
		if mapping.IsPathAllowed(path, "dev", "x") {
			t.Errorf("IsPathAllowed(%q) = true, want false", path)
		}
	}

	// Without an allowlist the rule is unchanged: the rendered path, and nothing else.
	plain := validMapping("dev")
	if !plain.IsPathAllowed(plain.RenderPath("dev", "x"), "dev", "x") {
		t.Error("the mapping's own rendered path was refused")
	}
	if plain.IsPathAllowed("apps/dev/../dev/x.yaml", "dev", "x") {
		t.Error("a non-canonical path passed a mapping with no allowlist")
	}
}

func TestProposalMappingRequiresAdapter(t *testing.T) {
	mapping := validMapping("default")
	mapping.Mode = GitDeliveryProposal
	if err := mapping.Validate(); err == nil {
		t.Fatal("proposal mapping without adapter was accepted")
	}
	mapping.ProposalAdapter = testProposalAdapter{}
	if err := mapping.Validate(); err != nil {
		t.Fatalf("mapping with adapter rejected: %v", err)
	}
}

func TestPolicyStoreGroupRoleAPIsFailClosed(t *testing.T) {
	store := NewPolicyStore()
	role, err := NewCustomRole("editor2", []Capability{SecretSeal})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddCustomRole(role); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGroupRoles("team", []string{"editor2"}); err != nil {
		t.Fatal(err)
	}
	if got := store.CapabilitiesForGroups([]string{"team"}); len(got) != 1 || got[0] != SecretSeal {
		t.Fatalf("got capabilities %v", got)
	}
	if err := store.SetGroupRoles("bad", []string{"missing"}); err == nil {
		t.Fatal("missing role mapping accepted")
	}
	if err := store.SetGroupRoles("team", []string{"editor2", "editor2"}); err == nil {
		t.Fatal("duplicate role mapping accepted")
	}
	if err := store.SetGroupRoles("", []string{"editor2"}); err == nil {
		t.Fatal("empty group accepted")
	}
}

func TestPolicyStoreConcurrentReadsAndWrites(t *testing.T) {
	store := NewPolicyStore()
	role, err := NewCustomRole("editor2", []Capability{SecretSeal})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddCustomRole(role); err != nil {
		t.Fatal(err)
	}
	mapping := validMapping("default")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = store.GetRole("editor2")
				_, _ = store.GetGitMapping("default")
				_ = store.CapabilitiesForGroups([]string{"team"})
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := store.SetGroupRoles("team", []string{"editor2"}); err != nil {
			t.Fatal(err)
		}
		if err := store.SetGitMapping(mapping); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
