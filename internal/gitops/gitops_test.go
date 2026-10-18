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

	diff, err := transport.DryRun(context.Background(), change, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(diff.Before, []byte("old")) || !bytes.Equal(diff.After, []byte("new")) || diff.BaseCommit != "abc" {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	snapshot, err := transport.ReadManifest(context.Background(), target, "")
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
	_, err := transport.PushBranch(context.Background(), Change{Target: target, BaseCommit: "stale", Content: []byte("new")}, "")
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
	if conflict.Expected != "stale" || conflict.Actual != "abc" {
		t.Fatalf("unexpected conflict: %#v", conflict)
	}
	snapshot, _ := transport.ReadManifest(context.Background(), target, "")
	if !bytes.Equal(snapshot.Content, []byte("old")) {
		t.Fatal("stale push changed content")
	}
}

// Pins the mock transport's agreement with GoGitTransport on the new-file case: a vacant path is
// not a conflict, because BaseCommit is compared against the branch head and not the absent
// file's own commit. Without this, mock mode could not create a first Secret in a namespace.
func TestLocalTransportCreatesANewFileOnTheBranchHead(t *testing.T) {
	transport := NewLocalTransport()
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "clusters/other.yaml"}, "other", "abc")
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/new.yaml"}

	vacant, err := transport.ReadManifest(context.Background(), target, "")
	if !errors.Is(err, ErrNotFound) || vacant.Commit != "abc" {
		t.Fatalf("vacant path = %#v, %v; want the branch head with ErrNotFound", vacant, err)
	}

	pushed, err := transport.PushBranch(context.Background(), Change{Target: target, BaseCommit: vacant.Commit, Content: []byte("new")}, "")
	if err != nil {
		t.Fatal(err)
	}
	readBack, err := transport.ReadManifest(context.Background(), target, "")
	if err != nil || string(readBack.Content) != "new" || readBack.Commit != pushed.Commit {
		t.Fatalf("new file not created: %#v, %v", readBack, err)
	}
}

// The mock's history is one version deep by construction, which is what a caller comparing a live
// Secret against the superseded content needs: a version nothing replaced yet has none.
func TestLocalTransportPreviousManifest(t *testing.T) {
	transport := NewLocalTransport()
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/app.yaml"}

	if _, err := transport.PreviousManifest(context.Background(), target, ""); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("unknown path error = %v, want ErrNoHistory", err)
	}

	transport.Seed(target, "first", "abc")
	if _, err := transport.PreviousManifest(context.Background(), target, ""); !errors.Is(err, ErrNoHistory) {
		t.Fatalf("first version error = %v, want ErrNoHistory", err)
	}

	transport.Seed(target, "second", "def")
	previous, err := transport.PreviousManifest(context.Background(), target, "")
	if err != nil || string(previous) != "first" {
		t.Fatalf("previous = %q, %v; want %q", previous, err, "first")
	}

	// A delivery replaces the file too, so what it replaced is the version a stale page's live
	// Secret would still match.
	if _, err := transport.PushBranch(context.Background(), Change{Target: target, BaseCommit: "def", Content: []byte("delivered")}, ""); err != nil {
		t.Fatal(err)
	}
	previous, err = transport.PreviousManifest(context.Background(), target, "")
	if err != nil || string(previous) != "second" {
		t.Fatalf("previous after push = %q, %v; want %q", previous, err, "second")
	}
}

func TestLocalTransportPushAndProposal(t *testing.T) {
	transport := NewLocalTransport()
	target := Target{Repository: "platform", Branch: "main", Path: "clusters/app.yaml"}
	transport.Seed(target, "old", "abc")
	change := Change{Target: target, BaseCommit: "abc", Content: []byte("new"), Branch: "proposal-1"}
	pusher := transport
	pushed, err := pusher.PushBranch(context.Background(), change, "")
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
	_, err := transport.DryRun(context.Background(), Change{Target: target, BaseCommit: "stale", Content: []byte("new")}, "")
	var baseErr *BaseCommitError
	if !errors.As(err, &baseErr) {
		t.Fatalf("error = %v, want BaseCommitError", err)
	}
}

// sealedDoc builds one SealedSecret document with a distinguishable ciphertext.
func sealedDoc(namespace, name, ciphertext string) string {
	return "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: " + name +
		"\n  namespace: " + namespace + "\nspec:\n  encryptedData:\n    key: " + ciphertext + "\n"
}

// multiDocFixture is a two-SealedSecret file whose second document names no namespace, so both
// matching rules (specific identity and name-only) are exercised against the same file.
func multiDocFixture() (string, string) {
	first := sealedDoc("payments", "api", "cipher-one")
	second := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: batch\nspec:\n  encryptedData:\n    key: cipher-two\n"
	return first + "---\n" + second, first
}

// TestSpliceSealedSecretPreservesSiblings pins the multi-document delivery contract: replacing one
// document leaves every other byte of the file identical, and the join round-trips the input.
func TestSpliceSealedSecretPreservesSiblings(t *testing.T) {
	file, first := multiDocFixture()
	replacement := sealedDoc("payments", "api", "cipher-one-new") + "\n"

	merged, ok := SpliceSealedSecret([]byte(file), []byte(replacement), "payments", "api")
	if !ok {
		t.Fatal("splice found no match")
	}
	want := replacement + "---\n" + file[len(first)+len("---\n"):]
	if !bytes.Equal(merged, []byte(want)) {
		t.Fatalf("sibling bytes changed: %q", string(merged))
	}
	// Re-splicing the merged file back to the original content must reproduce the original byte for byte.
	roundTrip, ok := SpliceSealedSecret(merged, []byte(first), "payments", "api")
	if !ok || !bytes.Equal(roundTrip, []byte(file)) {
		t.Fatalf("round-trip lost bytes: ok=%v %q", ok, string(roundTrip))
	}
}

func TestSpliceSealedSecretMatchesNameOnlyDocument(t *testing.T) {
	file, _ := multiDocFixture()
	replacement := sealedDoc("cluster", "batch", "cipher-two-new")

	merged, ok := SpliceSealedSecret([]byte(file), []byte(replacement), "prod", "batch")
	if !ok {
		t.Fatal("splice found no match")
	}
	if !bytes.Contains(merged, []byte("cipher-two-new")) || bytes.Contains(merged, []byte("key: cipher-two\n")) {
		t.Fatalf("name-only document not replaced: %q", string(merged))
	}
	if !bytes.Contains(merged, []byte("cipher-one")) {
		t.Fatalf("sibling lost: %q", string(merged))
	}
}

func TestSpliceSealedSecretNoMatchReturnsIncoming(t *testing.T) {
	file, _ := multiDocFixture()
	incoming := sealedDoc("payments", "other", "cipher-x")
	merged, ok := SpliceSealedSecret([]byte(file), []byte(incoming), "payments", "other")
	if ok {
		t.Fatal("splice claimed a match that does not exist")
	}
	if !bytes.Equal(merged, []byte(incoming)) {
		t.Fatalf("fallback altered incoming: %q", string(merged))
	}
}

func TestSpliceSealedSecretAddsTrailingNewline(t *testing.T) {
	file, _ := multiDocFixture()
	incoming := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: api\n  namespace: payments\nspec:\n  encryptedData:\n    key: new"
	merged, ok := SpliceSealedSecret([]byte(file), []byte(incoming), "payments", "api")
	if !ok {
		t.Fatal("splice found no match")
	}
	// The match is the first document, so the newline lands before the sibling separator, not at the file's end.
	if !bytes.Contains(merged, []byte("key: new\n---\n")) {
		t.Fatalf("incoming gained no separator newline: %q", string(merged))
	}
}
