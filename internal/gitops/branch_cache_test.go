package gitops

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBranchGit is a controllable GitTransport+BranchReader for the cache tests: it counts branch
// pulls, can be made to fail, and reports a settable commit so a refresh is observable.
type fakeBranchGit struct {
	mu          sync.Mutex
	branchReads int32
	pushes      int32
	commit      string
	err         error
	block       chan struct{} // when non-nil, ReadBranch waits on it before returning (single-flight test)
}

func (f *fakeBranchGit) ReadBranch(_ context.Context, _, _, _ string) (BranchSnapshot, error) {
	atomic.AddInt32(&f.branchReads, 1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return BranchSnapshot{}, f.err
	}
	return BranchSnapshot{Commit: f.commit, Files: map[string][]byte{"a.yaml": []byte("x")}}, nil
}

func (f *fakeBranchGit) setCommit(c string) { f.mu.Lock(); f.commit = c; f.mu.Unlock() }
func (f *fakeBranchGit) setErr(e error)     { f.mu.Lock(); f.err = e; f.mu.Unlock() }
func (f *fakeBranchGit) reads() int32       { return atomic.LoadInt32(&f.branchReads) }

func (f *fakeBranchGit) ReadManifest(context.Context, Target, string) (ManifestSnapshot, error) {
	return ManifestSnapshot{}, ErrNotFound
}
func (f *fakeBranchGit) SearchManifest(context.Context, string, string, string, string, string) (ManifestSnapshot, error) {
	return ManifestSnapshot{}, ErrNotFound
}
func (f *fakeBranchGit) DryRun(context.Context, Change, string) (Diff, error) { return Diff{}, nil }
func (f *fakeBranchGit) PushBranch(context.Context, Change, string) (PushResult, error) {
	atomic.AddInt32(&f.pushes, 1)
	return PushResult{}, nil
}

// newTestCache builds a cachingTransport with a fake clock the test advances by hand.
func newTestCache(t *testing.T, inner GitTransport, ttl time.Duration) (*cachingTransport, *fakeClock) {
	t.Helper()
	cache, ok := NewCachingTransport(inner, ttl).(*cachingTransport)
	if !ok {
		t.Fatalf("NewCachingTransport did not return a *cachingTransport")
	}
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache.now = clock.read
	return cache, clock
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) read() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeHistory adds a counting ManifestHistory to the branch fake; history reads are what a second
// detail view must not repeat once the head is known.
type fakeHistory struct {
	fakeBranchGit
	historyReads int32
	previous     []byte
}

func (f *fakeHistory) PreviousManifest(context.Context, Target, string) ([]byte, error) {
	atomic.AddInt32(&f.historyReads, 1)
	return f.previous, nil
}

func TestCachingTransport_PreviousManifestMemoizedByHead(t *testing.T) {
	inner := &fakeHistory{previous: []byte("older")}
	target := Target{Repository: "repo", Branch: "main", Path: "a.yaml"}
	inner.setCommit("c1")
	cache, clock := newTestCache(t, inner, time.Minute)

	if previous, err := cache.PreviousManifest(context.Background(), target, ""); err != nil || string(previous) != "older" {
		t.Fatalf("first read: %q, %v", previous, err)
	}
	if inner.historyReads != 1 {
		t.Fatalf("history reads after first read = %d, want 1", inner.historyReads)
	}

	// Repeated reads at the same head are answered from the memo — the slow path ran once.
	clock.advance(2 * time.Minute) // past the TTL: the branch snapshot revalidates, the memo still answers
	done := make(chan struct{}, 1)
	cache.refreshDone = func() { done <- struct{}{} }
	if _, err := cache.ReadBranch(context.Background(), "repo", "main", ""); err != nil {
		t.Fatal(err)
	}
	// The revalidation is detached, so it is awaited: a refresh still in flight below could repopulate
	// the entry with either head and make the final phase race.
	<-done
	for i := 0; i < 3; i++ {
		if previous, err := cache.PreviousManifest(context.Background(), target, ""); err != nil || string(previous) != "older" {
			t.Fatalf("read %d: %q, %v", i, previous, err)
		}
	}
	if inner.historyReads != 1 {
		t.Fatalf("history reads after same-head reads = %d, want 1", inner.historyReads)
	}

	// A new head is a new history: the memo misses and the content is re-read. The cache is
	// stale-while-revalidate, so the entry is invalidated to key the next read on the new head now.
	inner.setCommit("c2")
	inner.previous = []byte("newer")
	cache.invalidate("repo", "main")
	if previous, err := cache.PreviousManifest(context.Background(), target, ""); err != nil || string(previous) != "newer" {
		t.Fatalf("read at new head: %q, %v", previous, err)
	}
	if inner.historyReads != 2 {
		t.Fatalf("history reads after head advance = %d, want 2", inner.historyReads)
	}
}

func TestCachingTransport_DisabledPassthrough(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0"}
	if got := NewCachingTransport(inner, 0); got != GitTransport(inner) {
		t.Fatalf("ttl=0 should return inner unchanged, got %T", got)
	}
	if got := NewCachingTransport(nil, time.Second); got != nil {
		t.Fatalf("nil inner should return nil, got %T", got)
	}
	// A transport without ReadBranch cannot be memoized, so it passes through.
	plain := NewLocalTransport()
	if got := NewCachingTransport(plain, time.Second); got != GitTransport(plain) {
		t.Fatalf("non-BranchReader should return inner unchanged, got %T", got)
	}
}

func TestCachingTransport_ServesFreshFromCache(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0"}
	cache, clock := newTestCache(t, inner, 15*time.Second)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := cache.ReadBranch(ctx, "repo", "main", ""); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		clock.advance(time.Second) // still inside the 15s window
	}
	if got := inner.reads(); got != 1 {
		t.Fatalf("expected 1 pull inside the freshness window, got %d", got)
	}
}

func TestCachingTransport_StaleWhileRevalidate(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0"}
	cache, clock := newTestCache(t, inner, 15*time.Second)
	done := make(chan struct{}, 1)
	cache.refreshDone = func() { done <- struct{}{} }
	ctx := context.Background()

	first, err := cache.ReadBranch(ctx, "repo", "main", "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Commit != "c0" {
		t.Fatalf("first commit = %q", first.Commit)
	}

	// Move the remote forward and expire the entry. The next read must serve the stale c0 at once and
	// kick off a background refresh — not block on the pull.
	inner.setCommit("c1")
	clock.advance(16 * time.Second)
	stale, err := cache.ReadBranch(ctx, "repo", "main", "")
	if err != nil {
		t.Fatal(err)
	}
	if stale.Commit != "c0" {
		t.Fatalf("expected stale c0 while revalidating, got %q", stale.Commit)
	}

	<-done // background refresh finished
	fresh, err := cache.ReadBranch(ctx, "repo", "main", "")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Commit != "c1" {
		t.Fatalf("expected refreshed c1, got %q", fresh.Commit)
	}
	if got := inner.reads(); got != 2 {
		t.Fatalf("expected 2 pulls (cold + one refresh), got %d", got)
	}
}

func TestCachingTransport_ColdErrorPropagates(t *testing.T) {
	sentinel := errors.New("remote down")
	inner := &fakeBranchGit{err: sentinel}
	cache, _ := newTestCache(t, inner, 15*time.Second)
	if _, err := cache.ReadBranch(context.Background(), "repo", "main", ""); !errors.Is(err, sentinel) {
		t.Fatalf("expected cold error to propagate, got %v", err)
	}
}

func TestCachingTransport_FailedRefreshKeepsLastGood(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0"}
	cache, clock := newTestCache(t, inner, 15*time.Second)
	done := make(chan struct{}, 1)
	cache.refreshDone = func() { done <- struct{}{} }
	ctx := context.Background()

	if _, err := cache.ReadBranch(ctx, "repo", "main", ""); err != nil {
		t.Fatal(err)
	}
	inner.setErr(errors.New("transient"))
	clock.advance(16 * time.Second)

	stale, err := cache.ReadBranch(ctx, "repo", "main", "") // serves last-good, triggers failing refresh
	if err != nil {
		t.Fatalf("stale read should not surface the refresh error: %v", err)
	}
	if stale.Commit != "c0" {
		t.Fatalf("expected last-good c0, got %q", stale.Commit)
	}
	<-done
	again, err := cache.ReadBranch(ctx, "repo", "main", "")
	if err != nil {
		t.Fatalf("after failed refresh the last-good must still serve, got %v", err)
	}
	if again.Commit != "c0" {
		t.Fatalf("expected last-good c0 after failed refresh, got %q", again.Commit)
	}
}

func TestCachingTransport_PushInvalidates(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0"}
	cache, _ := newTestCache(t, inner, 15*time.Second)
	ctx := context.Background()

	if _, err := cache.ReadBranch(ctx, "repo", "main", ""); err != nil {
		t.Fatal(err)
	}
	inner.setCommit("c1")
	if _, err := cache.PushBranch(ctx, Change{Target: Target{Repository: "repo", Branch: "main"}}, ""); err != nil {
		t.Fatal(err)
	}
	// The push dropped the entry, so this read is cold and sees the post-push head immediately.
	got, err := cache.ReadBranch(ctx, "repo", "main", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Commit != "c1" {
		t.Fatalf("expected re-pull after push to see c1, got %q", got.Commit)
	}
	if reads := inner.reads(); reads != 2 {
		t.Fatalf("expected 2 pulls (before and after push), got %d", reads)
	}
}

func TestCachingTransport_SingleFlightOnCold(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0", block: make(chan struct{})}
	cache, _ := newTestCache(t, inner, 15*time.Second)
	ctx := context.Background()

	const callers = 8
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			_, _ = cache.ReadBranch(ctx, "repo", "main", "")
		}()
	}
	// Let the goroutines pile up on the cold entry, then release the single in-flight pull.
	time.Sleep(50 * time.Millisecond)
	close(inner.block)
	wg.Wait()

	if got := inner.reads(); got != 1 {
		t.Fatalf("expected a single shared pull for concurrent cold readers, got %d", got)
	}
}

func TestPrewarmBranchesWarmsTheCache(t *testing.T) {
	inner := &fakeBranchGit{commit: "c0"}
	cache, _ := newTestCache(t, inner, 15*time.Second)

	// Duplicate (repo,branch) and an empty entry are both dropped, so the one real branch is pulled
	// exactly once.
	PrewarmBranches(context.Background(), cache, []WarmTarget{
		{Repository: "repo", Branch: "main", AuthRef: ""},
		{Repository: "repo", Branch: "main", AuthRef: ""},
		{Repository: "", Branch: "main"},
	}, nil)
	if got := inner.reads(); got != 1 {
		t.Fatalf("prewarm should pull the one distinct branch once, got %d", got)
	}

	// A request after warming is served from the cache rather than pulling again — the point of
	// prewarming is that the first user request is already warm.
	if _, err := cache.ReadBranch(context.Background(), "repo", "main", ""); err != nil {
		t.Fatal(err)
	}
	if got := inner.reads(); got != 1 {
		t.Fatalf("post-prewarm read should be served from cache, got %d pulls", got)
	}
}

func TestPrewarmBranchesIgnoresNonBranchReader(t *testing.T) {
	// A transport that cannot enumerate a branch (caching disabled, or mock mode) is a no-op rather
	// than a panic.
	PrewarmBranches(context.Background(), NewLocalTransport(), []WarmTarget{{Repository: "r", Branch: "main"}}, nil)
}
