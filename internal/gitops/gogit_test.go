package gitops

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// bareRemote initializes a local bare repository and seeds an initial
// commit on the given branch through the system git binary. Bare remotes
// verify provider-neutral transport per the phase-4 verification plan.
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

	// Dry-run returns the before/after without mutating the remote.
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

	// Push lands on the remote and the read-back matches.
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

	// A new-file change against an empty base pushes and creates the path.
	snapshot, err := transport.ReadManifest(ctx, Target{Repository: remoteURL, Branch: "main", Path: "other/README.md"}, "")
	if err != nil {
		t.Fatal(err)
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

	// Rotation: rewriting the file takes effect on the next resolve.
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
