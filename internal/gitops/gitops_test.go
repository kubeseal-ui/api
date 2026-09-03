package gitops

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestLocalTransportDryRunDoesNotMutate(t *testing.T) {
	transport := NewLocalTransport()
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/app.yaml"}
	transport.Seed(target, "old", "abc")
	change := Change{Target: target, BaseCommit: "abc", Content: []byte("new")}

	diff, err := transport.DryRun(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diff.Before, []byte("old")) || !bytes.Equal(diff.After, []byte("new")) || diff.BaseCommit != "abc" {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	snapshot, err := transport.ReadManifest(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshot.Content, []byte("old")) || snapshot.Commit != "abc" {
		t.Fatalf("dry-run mutated state: %#v", snapshot)
	}
}

func TestLocalTransportPushRejectsStaleBaseWithoutForce(t *testing.T) {
	transport := NewLocalTransport()
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/app.yaml"}
	transport.Seed(target, "old", "abc")
	_, err := transport.PushBranch(context.Background(), Change{Target: target, BaseCommit: "stale", Content: []byte("new")})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
	if conflict.Expected != "stale" || conflict.Actual != "abc" {
		t.Fatalf("unexpected conflict: %#v", conflict)
	}
	snapshot, _ := transport.ReadManifest(context.Background(), target)
	if !bytes.Equal(snapshot.Content, []byte("old")) {
		t.Fatal("stale push changed content")
	}
}

func TestLocalTransportPushAndProposal(t *testing.T) {
	transport := NewLocalTransport()
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/app.yaml"}
	transport.Seed(target, "old", "abc")
	change := Change{Target: target, BaseCommit: "abc", Content: []byte("new"), Branch: "proposal-1"}
	pusher := transport
	pushed, err := pusher.PushBranch(context.Background(), change)
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Branch != "proposal-1" || pushed.Commit == "" {
		t.Fatalf("unexpected push: %#v", pushed)
	}
	provider := LocalProposalProvider{URLPrefix: "https://review.test"}
	proposal, err := provider.OpenProposal(context.Background(), ProposalRequest{Change: change, Push: pushed, Title: "Update secret"})
	if err != nil {
		t.Fatal(err)
	}
	if proposal.URL != "https://review.test/platform/proposal-1" || proposal.Commit != pushed.Commit {
		t.Fatalf("unexpected proposal: %#v", proposal)
	}
}

func TestLocalTransportDryRunRejectsStaleBase(t *testing.T) {
	transport := NewLocalTransport()
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/app.yaml"}
	transport.Seed(target, "old", "abc")
	_, err := transport.DryRun(context.Background(), Change{Target: target, BaseCommit: "stale", Content: []byte("new")})
	var baseErr *BaseCommitError
	if !errors.As(err, &baseErr) {
		t.Fatalf("error = %v, want BaseCommitError", err)
	}
}
