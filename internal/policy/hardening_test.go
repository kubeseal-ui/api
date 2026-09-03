package policy

import (
	"context"
	"sync"
	"testing"
)

type testProposalAdapter struct{}

func (testProposalAdapter) OpenProposal(context.Context, ProposalRequest) (ProposalResult, error) {
	return ProposalResult{}, nil
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
