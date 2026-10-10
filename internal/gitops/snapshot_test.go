package gitops

import (
	"context"
	"errors"
	"testing"
)

type transportCounts struct {
	branchReads int
	reads       int
	searches    int
	dryRuns     int
	pushes      int
}

// countingGit delegates to a LocalTransport and counts the calls. It has no ReadBranch on
// purpose: a transport that cannot enumerate a branch is the degradation case SnapshotTransport
// must pass through untouched.
type countingGit struct {
	*LocalTransport
	counts *transportCounts
}

func (c *countingGit) ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error) {
	c.counts.reads++
	return c.LocalTransport.ReadManifest(ctx, target, authRef)
}

func (c *countingGit) SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error) {
	c.counts.searches++
	return c.LocalTransport.SearchManifest(ctx, repository, branch, namespace, name, authRef)
}

func (c *countingGit) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	c.counts.dryRuns++
	return c.LocalTransport.DryRun(ctx, change, authRef)
}

func (c *countingGit) PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error) {
	c.counts.pushes++
	return c.LocalTransport.PushBranch(ctx, change, authRef)
}

// branchCounting adds the BranchReader capability, which is what turns memoization on.
type branchCounting struct {
	*countingGit
}

func (c *branchCounting) ReadBranch(_ context.Context, repository, branch, _ string) (BranchSnapshot, error) {
	c.counts.branchReads++
	c.LocalTransport.mu.RLock()
	defer c.LocalTransport.mu.RUnlock()
	files := map[string][]byte{}
	for target, entry := range c.LocalTransport.entries {
		if target.Repository == repository && target.Branch == branch {
			files[target.Path] = append([]byte(nil), entry.content...)
		}
	}
	return BranchSnapshot{Commit: c.LocalTransport.heads[branchKey(repository, branch)], Files: files}, nil
}

const apiSealedSecret = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: api
  namespace: payments
spec:
  template:
    metadata:
      namespace: payments
`

func countingBranchTransport(t *testing.T) (*branchCounting, *transportCounts) {
	t.Helper()
	counts := &transportCounts{}
	inner := NewLocalTransport()
	return &branchCounting{countingGit: &countingGit{LocalTransport: inner, counts: counts}}, counts
}

// A namespace listing resolves drift for every Secret it returns, so all of those reads share one
// branch and one moment and must cost one fetch — not one per read.
func TestSnapshotServesEveryReadFromOneBranchLoad(t *testing.T) {
	transport, counts := countingBranchTransport(t)
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, apiSealedSecret, "abc")
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "clusters/payments/db.yaml"}, "apiVersion: v1\nkind: Secret\n", "abc")
	snapshot := NewSnapshotTransport(transport)

	hit, err := snapshot.ReadManifest(t.Context(), Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "auth")
	if err != nil {
		t.Fatalf("read hit: %v", err)
	}
	if string(hit.Content) != apiSealedSecret || hit.Commit != "abc" {
		t.Fatalf("hit = %+v", hit)
	}
	if _, err := snapshot.ReadManifest(t.Context(), Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "auth"); err != nil {
		t.Fatalf("second read: %v", err)
	}
	found, err := snapshot.SearchManifest(t.Context(), "platform", "main", "payments", "api", "auth")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if found.Target.Path != "clusters/payments/api.yaml" {
		t.Fatalf("search path = %q", found.Target.Path)
	}

	if counts.branchReads != 1 {
		t.Fatalf("branch reads = %d, want 1", counts.branchReads)
	}
	if counts.reads != 0 || counts.searches != 0 {
		t.Fatalf("reads = %d, searches = %d; the snapshot must answer both", counts.reads, counts.searches)
	}
}

// The memo is per branch, not request-global: a namespace mapped across two branches costs two
// loads and no more.
func TestSnapshotLoadsEachBranchOnce(t *testing.T) {
	transport, counts := countingBranchTransport(t)
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, "one", "main-head")
	transport.Seed(Target{Repository: "platform", Branch: "staging", Path: "a.yaml"}, "two", "staging-head")
	snapshot := NewSnapshotTransport(transport)

	for _, branch := range []string{"main", "staging", "main", "staging"} {
		if _, err := snapshot.ReadManifest(t.Context(), Target{Repository: "platform", Branch: branch, Path: "a.yaml"}, "auth"); err != nil {
			t.Fatalf("read %s: %v", branch, err)
		}
	}
	if counts.branchReads != 2 {
		t.Fatalf("branch reads = %d, want 2 (one per branch)", counts.branchReads)
	}
}

// A path not in the snapshot is ErrNotFound, and the snapshot still carries the head a BaseCommit
// is compared against — without it a namespace with no secrets yet could not create one.
func TestSnapshotReportsAVacantPathWithTheBranchHead(t *testing.T) {
	transport, _ := countingBranchTransport(t)
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, "one", "abc")
	snapshot := NewSnapshotTransport(transport)

	missing, err := snapshot.ReadManifest(t.Context(), Target{Repository: "platform", Branch: "main", Path: "clusters/payments/new.yaml"}, "auth")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if missing.Commit != "abc" {
		t.Fatalf("commit = %q, want the branch head", missing.Commit)
	}
	if missing.Target.Path != "clusters/payments/new.yaml" {
		t.Fatalf("target = %+v, want the requested path", missing.Target)
	}
}

// Two files claiming the same identity is a misconfiguration, but map iteration order is random,
// so without the sort the reported path — and the drift it implies — would flap between requests.
func TestSnapshotSearchIsDeterministic(t *testing.T) {
	transport, _ := countingBranchTransport(t)
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "z-last.yaml"}, apiSealedSecret, "abc")
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "a-first.yaml"}, apiSealedSecret, "abc")
	snapshot := NewSnapshotTransport(transport)

	for i := 0; i < 8; i++ {
		found, err := snapshot.SearchManifest(t.Context(), "platform", "main", "payments", "api", "auth")
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		if found.Target.Path != "a-first.yaml" {
			t.Fatalf("search path = %q, want the lexicographically first match", found.Target.Path)
		}
	}
}

// The snapshot is a read memo only: a push must reach the transport, and the branch it touched
// must be dropped so a later read re-reads instead of reporting what the push replaced.
func TestSnapshotNeverServesWritesFromTheCache(t *testing.T) {
	transport, counts := countingBranchTransport(t)
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, "before", "abc")
	snapshot := NewSnapshotTransport(transport)
	target := Target{Repository: "platform", Branch: "main", Path: "a.yaml"}

	if _, err := snapshot.ReadManifest(t.Context(), target, "auth"); err != nil {
		t.Fatalf("seed read: %v", err)
	}
	pushed, err := snapshot.PushBranch(t.Context(), Change{Target: target, BaseCommit: "abc", Content: []byte("after")}, "auth")
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if counts.pushes != 1 {
		t.Fatalf("pushes = %d, want 1 — writes must reach the transport", counts.pushes)
	}

	after, err := snapshot.ReadManifest(t.Context(), target, "auth")
	if err != nil {
		t.Fatalf("read after push: %v", err)
	}
	if string(after.Content) != "after" {
		t.Fatalf("content = %q, want the pushed content", after.Content)
	}
	if after.Commit != pushed.Commit {
		t.Fatalf("commit = %q, want the pushed commit %q", after.Commit, pushed.Commit)
	}
	if counts.branchReads != 2 {
		t.Fatalf("branch reads = %d, want 2 — the push must drop the snapshot", counts.branchReads)
	}
}

// Mock mode and any transport that cannot enumerate a branch must behave exactly as they did
// before the wrapper existed: every read goes straight through.
func TestSnapshotPassesThroughWithoutABranchReader(t *testing.T) {
	counts := &transportCounts{}
	inner := NewLocalTransport()
	transport := &countingGit{LocalTransport: inner, counts: counts}
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, apiSealedSecret, "abc")
	snapshot := NewSnapshotTransport(transport)

	snapshot.ReadManifest(t.Context(), Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, "auth")
	snapshot.ReadManifest(t.Context(), Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, "auth")
	if _, err := snapshot.SearchManifest(t.Context(), "platform", "main", "payments", "api", "auth"); err != nil {
		t.Fatalf("search: %v", err)
	}

	if counts.branchReads != 0 {
		t.Fatalf("branch reads = %d, want 0 — there is no branch reader to use", counts.branchReads)
	}
	if counts.reads != 2 || counts.searches != 1 {
		t.Fatalf("reads = %d, searches = %d; every call must pass through", counts.reads, counts.searches)
	}
}

// A dry run exists to compare the caller's base against the live head; answering it from the
// snapshot would defeat the check the write path depends on.
func TestSnapshotDryRunIsNeverMemoized(t *testing.T) {
	transport, counts := countingBranchTransport(t)
	transport.Seed(Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, "before", "abc")
	snapshot := NewSnapshotTransport(transport)
	change := Change{Target: Target{Repository: "platform", Branch: "main", Path: "a.yaml"}, BaseCommit: "abc", Content: []byte("after")}

	for i := 0; i < 2; i++ {
		if _, err := snapshot.DryRun(t.Context(), change, "auth"); err != nil {
			t.Fatalf("dry run: %v", err)
		}
	}
	if counts.dryRuns != 2 {
		t.Fatalf("dry runs = %d, want 2", counts.dryRuns)
	}
}
