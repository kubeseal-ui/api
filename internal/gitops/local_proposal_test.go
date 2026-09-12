package gitops

import (
	"context"
	"fmt"
	"testing"
)

// TestProposalPushDoesNotTouchDirectBranch pins the proposal-mode contract:
// a branch push targets the proposal branch; the direct branch keeps its
// content until a direct delivery lands.
func TestProposalPushDoesNotTouchDirectBranch(t *testing.T) {
	transport := NewLocalTransport()
	direct := Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}
	transport.Seed(direct, "old", "abc")

	pushed, err := transport.PushBranch(context.Background(), Change{Target: direct, BaseCommit: "abc", Content: []byte("new"), Branch: "proposal-1"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Branch != "proposal-1" {
		t.Fatalf("pushed.Branch = %q, want proposal-1", pushed.Branch)
	}

	// The direct branch is untouched.
	snapshot, err := transport.ReadManifest(context.Background(), direct, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != "old" {
		t.Fatalf("direct branch changed: %q", snapshot.Content)
	}

	// The proposal branch carries the change.
	proposal, err := transport.ReadManifest(context.Background(), Target{Repository: "platform", Branch: "proposal-1", Path: "clusters/payments/api.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(proposal.Content) != "new" || proposal.Commit != pushed.Commit {
		t.Fatalf("proposal branch mismatch: %#v vs %#v", proposal, pushed)
	}
	fmt.Println("contract verified")
}
