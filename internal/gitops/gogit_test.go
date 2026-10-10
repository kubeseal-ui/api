package gitops

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// bareRemote initializes a local bare repository with an initial commit on the given branch,
// through the system git binary.
func bareRemote(t *testing.T, dir, branch string) string {
	t.Helper()
	cmd := exec.Command("git", "init", "--bare", "--initial-branch", branch, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return dir
}

func seedWorktree(t *testing.T, dir, remote, branch, path, content string) string {
	t.Helper()
	cmd := exec.Command("git", "clone", remote, dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone: %v\n%s", err, out)
	}
	run := func(args ...string) {
		t.Helper()
		inner := exec.Command("git", args...)
		inner.Dir = dir
		if out, err := inner.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	run("checkout", "-b", branch)
	if path != "" {
		parent := filepath.Dir(filepath.Join(dir, path))
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		run("add", path)
		run("commit", "-m", "seed")
		run("push", "-u", "origin", branch)
	}
	return dir
}

func headCommit(t *testing.T, dir, branch string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "rev-parse", branch)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rev-parse: %v", err)
	}
	return string(out[:len(out)-1])
}

func fileAtBranch(t *testing.T, dir, branch, path string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "show", branch+":"+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("show %s:%s: %v", branch, path, err)
	}
	return string(out)
}

func TestGoGitTransportRoundTripAgainstBareRemote(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "clusters/payments/api.yaml", "before-content")

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := Target{Repository: remoteURL, Branch: "main", Path: "clusters/payments/api.yaml"}

	snapshot, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != "before-content" || snapshot.Commit == "" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}

	diff, err := transport.DryRun(ctx, Change{Target: target, BaseCommit: snapshot.Commit, Content: []byte("after-content")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(diff.Before) != "before-content" || string(diff.After) != "after-content" {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	again, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Content) != "before-content" {
		t.Fatal("dry-run mutated the remote")
	}

	pushed, err := transport.PushBranch(ctx, Change{Target: target, BaseCommit: snapshot.Commit, Content: []byte("after-content")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Commit == "" || pushed.Branch != "main" {
		t.Fatalf("unexpected push: %#v", pushed)
	}
	readBack, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(readBack.Content) != "after-content" || readBack.Commit != pushed.Commit {
		t.Fatalf("read-back mismatch: %#v vs %#v", readBack, pushed)
	}
}

// A proposal push must exist on the remote under its own branch. Nothing creates that branch
// locally, and go-git silently pushes nothing when the refspec source is missing, so this asserts
// against a real remote rather than a transport that synthesises the branch.
func TestGoGitTransportProposalPushLandsItsOwnBranch(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "clusters/payments/api.yaml", "before-content")

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := Target{Repository: remoteURL, Branch: "main", Path: "clusters/payments/api.yaml"}

	snapshot, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	proposal := "kubeseal-ui/cluster-api"
	pushed, err := transport.PushBranch(ctx, Change{
		Target:     target,
		Branch:     proposal,
		BaseCommit: snapshot.Commit,
		Content:    []byte("after-content"),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if pushed.Branch != proposal {
		t.Fatalf("push reported branch %q, want %q", pushed.Branch, proposal)
	}
	if got := headCommit(t, remote, proposal); got != pushed.Commit {
		t.Fatalf("proposal branch head %q, reported %q", got, pushed.Commit)
	}
	if got := fileAtBranch(t, remote, proposal, target.Path); got != "after-content" {
		t.Fatalf("proposal branch content %q, want %q", got, "after-content")
	}
	if got := headCommit(t, remote, "main"); got != snapshot.Commit {
		t.Fatalf("proposal push moved the target branch to %q, want %q", got, snapshot.Commit)
	}
}

// A retry of a delivery that landed still carries the base the first push moved, so the stale-base
// guard would refuse work that is already done. Content equality is therefore checked first: the
// file holds exactly the requested bytes, and the answer is the commit that put them there. A stale
// base whose content differs is still a conflict — that is the case the guard exists for.
func TestGoGitTransportRetryOfLandedContentIsNotAConflict(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "clusters/payments/api.yaml", "before-content")

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := Target{Repository: remoteURL, Branch: "main", Path: "clusters/payments/api.yaml"}

	first, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	change := Change{Target: target, BaseCommit: first.Commit, Content: []byte("after-content")}
	pushed, err := transport.PushBranch(ctx, change, "")
	if err != nil {
		t.Fatal(err)
	}

	retried, err := transport.PushBranch(ctx, change, "")
	if err != nil {
		t.Fatalf("retry of a landed delivery: %v", err)
	}
	if retried.Commit != pushed.Commit {
		t.Fatalf("retry reported commit %q, want the delivered %q", retried.Commit, pushed.Commit)
	}

	stale := Change{Target: target, BaseCommit: first.Commit, Content: []byte("other-content")}
	_, err = transport.PushBranch(ctx, stale, "")
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError for a stale base over new content", err)
	}
}

// One GoGitTransport serves the whole process and its checkout is keyed on repository and branch, so
// concurrent deliveries for one namespace share one directory, one index and one HEAD. Serialised,
// they converge on a single commit; interleaved, one request's Add and Commit can sweep in the
// other's staged path or fail outright on a dirty worktree.
func TestGoGitTransportConcurrentDeliveriesConvergeOnOneCommit(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "clusters/payments/api.yaml", "before-content")

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := Target{Repository: remoteURL, Branch: "main", Path: "clusters/payments/api.yaml"}
	seed, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}

	// Every delivery carries the same base, which only the first of them will still find at head.
	const deliveries = 4
	results := make([]PushResult, deliveries)
	errs := make([]error, deliveries)
	var wg sync.WaitGroup
	for i := range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = transport.PushBranch(ctx, Change{Target: target, BaseCommit: seed.Commit, Content: []byte("after-content")}, "")
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
		if results[i].Commit != results[0].Commit {
			t.Fatalf("delivery %d reported commit %q, want the one commit %q", i, results[i].Commit, results[0].Commit)
		}
	}
	// The seed and one delivery: the deliveries that lost the race found the content already at head
	// rather than adding a commit of their own for it.
	if got := commitCount(t, remote, "main"); got != "2" {
		t.Fatalf("branch holds %s commits, want the seed and one delivery", got)
	}
}

func commitCount(t *testing.T, dir, branch string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "rev-list", "--count", branch)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rev-list: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func TestGoGitTransportRejectsStaleBase(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "clusters/payments/api.yaml", "content")

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := Target{Repository: remoteURL, Branch: "main", Path: "clusters/payments/api.yaml"}

	_, err = transport.DryRun(ctx, Change{Target: target, BaseCommit: "deadbeef", Content: []byte("x")}, "")
	var baseErr *BaseCommitError
	if !errors.As(err, &baseErr) {
		t.Fatalf("error = %v, want BaseCommitError", err)
	}

	_, err = transport.PushBranch(ctx, Change{Target: target, BaseCommit: "deadbeef", Content: []byte("x")}, "")
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error = %v, want ConflictError", err)
	}
}

func TestGoGitTransportMissingMappedFileIsVacancy(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "other/README.md", "seed")

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target := Target{Repository: remoteURL, Branch: "main", Path: "clusters/payments/new-cred.yaml"}

	_, err = transport.ReadManifest(ctx, target, "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}

	// The vacancy sentinel is not a zero snapshot: it carries the branch head, which is what a
	// create must build on and what the new-secret flow reports to the client.
	vacant, err := transport.ReadManifest(ctx, target, "")
	if vacant.Commit == "" || vacant.Target.Path != target.Path {
		t.Fatalf("vacancy snapshot lost the branch head: %#v (err = %v)", vacant, err)
	}

	snapshot, err := transport.ReadManifest(ctx, Target{Repository: remoteURL, Branch: "main", Path: "other/README.md"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Commit != vacant.Commit {
		t.Fatalf("vacant-path head %q != branch head %q", vacant.Commit, snapshot.Commit)
	}
	pushed, err := transport.PushBranch(ctx, Change{Target: target, BaseCommit: snapshot.Commit, Content: []byte("new-file")}, "")
	if err != nil {
		t.Fatal(err)
	}
	readBack, err := transport.ReadManifest(ctx, target, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(readBack.Content) != "new-file" || readBack.Commit != pushed.Commit {
		t.Fatalf("new-file vacancy not filled: %#v", readBack)
	}
}

func TestGoGitTransportPathConfinement(t *testing.T) {
	scratch := t.TempDir()
	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: scratch})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"../escape.yaml", "/absolute.yaml", "a/../../b.yaml"} {
		got := transport.worktreePath(Target{Repository: "platform", Branch: "main", Path: path})
		rel, relErr := filepath.Rel(scratch, got)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			t.Fatalf("path %q escaped scratch: %q", path, got)
		}
	}
}

func TestCredentialHTTPSTokenBuildsBasicAuth(t *testing.T) {
	credential := Credential{Mode: AuthModeHTTPSToken, Username: "svc-account", Token: "tok-123"}
	if err := credential.Validate(); err != nil {
		t.Fatal(err)
	}
	method, err := credential.transportAuth()
	if err != nil {
		t.Fatal(err)
	}
	if method == nil {
		t.Fatal("https-token credential must produce an auth method")
	}
}

func TestCredentialValidation(t *testing.T) {
	if err := (Credential{Mode: AuthModeHTTPSToken}).Validate(); err == nil {
		t.Fatal("https-token without token must fail")
	}
	if err := (Credential{Mode: AuthModeHTTPSToken, Token: "a", TokenFile: "/b"}).Validate(); err == nil {
		t.Fatal("https-token with both token and file must fail")
	}
	if err := (Credential{Mode: AuthModeNone, Token: "a"}).Validate(); err == nil {
		t.Fatal("none credential with values must fail")
	}
	if _, err := ParseAuthMode("basic"); err == nil {
		t.Fatal("unknown auth mode must fail")
	}
	if _, err := ParseAuthMode("ssh-agent"); err != nil {
		t.Fatalf("ssh-agent must parse: %v", err)
	}
}

func TestFileCredentialResolverReadsTokenPerCall(t *testing.T) {
	tokenFile := t.TempDir() + "/token"
	if err := writeFile(tokenFile, "first-token\n"); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewFileCredentialResolver([]FileCredential{{AuthRef: "git-auth", Mode: AuthModeHTTPSToken, Username: "svc", TokenFile: tokenFile}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := resolver.Resolve(context.Background(), "org/repo", "git-auth")
	if err != nil {
		t.Fatal(err)
	}
	method, err := credential.transportAuth()
	if err != nil {
		t.Fatal(err)
	}
	if method == nil {
		t.Fatal("resolved credential must produce an auth method")
	}

	if err := writeFile(tokenFile, "rotated-token"); err != nil {
		t.Fatal(err)
	}
	rotated, err := resolver.Resolve(context.Background(), "org/repo", "git-auth")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.TokenFile != tokenFile {
		t.Fatalf("unexpected rotated credential: %#v", rotated)
	}
}

func writeFile(path, content string) error {
	return execWrite(path, content)
}

func execWrite(path, content string) error {
	cmd := exec.Command("sh", "-c", "printf '%s' '"+content+"' > "+path)
	return cmd.Run()
}

func TestUnknownCredentialReferenceFailsClosed(t *testing.T) {
	resolver := NewStaticCredentialResolver(nil)
	if _, err := resolver.Resolve(context.Background(), "org/repo", "missing"); err == nil {
		t.Fatal("unknown auth reference must fail closed")
	}
	var nilResolver *StaticCredentialResolver
	if _, err := nilResolver.Resolve(context.Background(), "org/repo", "x"); err == nil {
		t.Fatal("nil resolver must fail closed")
	}
}

func TestGoGitTransportSearchManifestOptionA(t *testing.T) {
	remote := bareRemote(t, t.TempDir()+"/remote.git", "main")
	remoteURL := "file://" + remote
	yamlContent := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: my-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    token: cipher123\n"
	seedWorktree(t, t.TempDir()+"/seed", remoteURL, "main", "apps/infra/nested/my-cred.yaml", yamlContent)

	transport, err := NewGoGitTransport(GoGitOptions{ScratchDir: t.TempDir(), AuthorEmail: "kubeseal-ui@test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	snap, err := transport.SearchManifest(ctx, remoteURL, "main", "cluster", "my-cred", "")
	if err != nil {
		t.Fatalf("SearchManifest failed: %v", err)
	}
	if snap.Target.Path != "apps/infra/nested/my-cred.yaml" {
		t.Fatalf("expected path apps/infra/nested/my-cred.yaml, got %q", snap.Target.Path)
	}
	if string(snap.Content) != yamlContent {
		t.Fatalf("content mismatch: %q", string(snap.Content))
	}

	_, err = transport.SearchManifest(ctx, remoteURL, "main", "cluster", "non-existent", "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
