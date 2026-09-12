package policy

import (
	"context"
	"strings"
	"testing"
)

type seedAdapter struct{}

func (seedAdapter) OpenProposal(context.Context, ProposalRequest) (ProposalResult, error) {
	return ProposalResult{}, nil
}

func TestSeedGitMappingsSeedsDirectAndProposal(t *testing.T) {
	store := NewPolicyStore()
	specs := []GitMappingSpec{
		{Namespace: "payments", Repository: "org/repo", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "platform-cred", Mode: GitDeliveryDirect},
		{Namespace: "staging", Repository: "org/repo", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "platform-cred", Mode: GitDeliveryProposal, ProposalAdapterName: "github-pr"},
	}
	if err := store.SeedGitMappings(specs, map[string]ProposalAdapter{"github-pr": seedAdapter{}}); err != nil {
		t.Fatal(err)
	}
	direct, ok := store.GetGitMapping("payments")
	if !ok || direct.Mode != GitDeliveryDirect || direct.ProposalAdapter != nil {
		t.Fatalf("unexpected direct mapping: %#v", direct)
	}
	proposal, ok := store.GetGitMapping("staging")
	if !ok || proposal.Mode != GitDeliveryProposal || proposal.ProposalAdapter == nil {
		t.Fatalf("proposal adapter not resolved: %#v", proposal)
	}
}

func TestSeedGitMappingsUnknownAdapterFailsClosed(t *testing.T) {
	store := NewPolicyStore()
	specs := []GitMappingSpec{
		{Namespace: "staging", Repository: "org/repo", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "cred", Mode: GitDeliveryProposal, ProposalAdapterName: "missing"},
	}
	err := store.SeedGitMappings(specs, map[string]ProposalAdapter{})
	if err == nil || !strings.Contains(err.Error(), "unknown proposal adapter") {
		t.Fatalf("err = %v, want unknown proposal adapter", err)
	}
	// The store stays empty after a failed seeding.
	if _, ok := store.GetGitMapping("staging"); ok {
		t.Fatal("failed seeding left a mapping behind")
	}
}

func TestSeedGitMappingsProposalValidationStillApplies(t *testing.T) {
	store := NewPolicyStore()
	// A proposal spec with a resolved adapter but an unsafe path template fails validation.
	specs := []GitMappingSpec{
		{Namespace: "staging", Repository: "org/repo", Branch: "main", PathTemplate: "../{namespace}/{name}.yaml", AuthRef: "cred", Mode: GitDeliveryProposal, ProposalAdapterName: "github-pr"},
	}
	if err := store.SeedGitMappings(specs, map[string]ProposalAdapter{"github-pr": seedAdapter{}}); err == nil {
		t.Fatal("unsafe path template must fail validation")
	}
}
