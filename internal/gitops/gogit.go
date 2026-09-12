// go-git implementation of the platform-neutral GitTransport contract.
//
// Phase 4 contract: portable fetch, commit, and push against any
// compatible remote. Implementations must never force-push, reset,
// rebase, or retry; a conflicting push surfaces ConflictError so the
// handler can return 409 immediately.
package gitops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// GoGitTransport performs real Git operations through go-git.
// The worktree is per-target under a scratch directory; fetch is
// repeated per call so the live remote state is always observed.
type GoGitTransport struct {
	// scratch is the parent directory for per-target worktrees.
	scratch string
	// authorName and authorEmail stamp every delivery commit.
	authorName  string
	authorEmail string
	// credentials resolves typed auth per repository/auth reference.
	credentials CredentialResolver
	// now is overridable in tests.
	now func() time.Time
}

// GoGitOptions configures the transport.
type GoGitOptions struct {
	// ScratchDir holds per-target worktrees. Defaults to
	// os.TempDir()/kubeseal-ui-gitops.
	ScratchDir string
	// AuthorName stamps delivery commits. Defaults to "kubeseal-ui".
	AuthorName string
	// AuthorEmail stamps delivery commits.
	AuthorEmail string
	// Credentials resolves typed auth; may be nil for open remotes.
	Credentials CredentialResolver
}

// NewGoGitTransport builds the transport and prepares the scratch root.
func NewGoGitTransport(options GoGitOptions) (*GoGitTransport, error) {
	scratch := options.ScratchDir
	if scratch == "" {
		scratch = filepath.Join(os.TempDir(), "kubeseal-ui-gitops")
	}
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return nil, fmt.Errorf("create scratch dir: %w", err)
	}
	authorName := options.AuthorName
	if authorName == "" {
		authorName = "kubeseal-ui"
	}
	return &GoGitTransport{
		scratch:     scratch,
		authorName:  authorName,
		authorEmail: options.AuthorEmail,
		credentials: options.Credentials,
		now:         time.Now,
	}, nil
}

// worktreePath derives a filesystem-safe directory per repository+branch.
func (t *GoGitTransport) worktreePath(target Target) string {
	safe := func(value string) string {
		replaced := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
				return r
			}
			return '_'
		}, value)
		return replaced
	}
	return filepath.Join(t.scratch, safe(target.Repository), safe(target.Branch))
}

// authFor resolves credentials for a target. An explicitly configured
// "none" mode yields nil auth; a resolver miss is an error, never an
// implicit anonymous push.
func (t *GoGitTransport) authFor(ctx context.Context, target Target, authRef string) (transport.AuthMethod, error) {
	if t.credentials == nil {
		return nil, nil
	}
	credential, err := t.credentials.Resolve(ctx, target.Repository, authRef)
	if err != nil {
		return nil, err
	}
	return credential.transportAuth()
}

// openOrClone returns the repository worktree for a target, cloning when
// the scratch directory has no checkout yet.
func (t *GoGitTransport) openOrClone(ctx context.Context, target Target, auth transport.AuthMethod) (*git.Repository, error) {
	path := t.worktreePath(target)
	if _, statErr := os.Stat(path); statErr == nil {
		if repo, openErr := git.PlainOpen(path); openErr == nil {
			return repo, nil
		}
		// A broken scratch entry is re-cloned, not trusted. Removal
		// failure only forces a fresh clone to fail loudly below.
		if removeErr := os.RemoveAll(path); removeErr != nil {
			return nil, fmt.Errorf("reset broken worktree %s: %w", path, removeErr)
		}
	}
	return git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:           remoteURL(target),
		ReferenceName: plumbing.NewBranchReferenceName(target.Branch),
		SingleBranch:  true,
		Depth:         1,
		Auth:          auth,
	})
}

func remoteURL(target Target) string {
	if strings.Contains(target.Repository, "://") || strings.Contains(target.Repository, "@") {
		return target.Repository
	}
	return "https://git.example.com/" + target.Repository + ".git"
}

// ReadManifest fetches the remote and reads the file content at a target.
// It returns ErrNotFound when the mapped file does not exist yet — the
// new-file vacancy case — and surfaces fetch failures as transport errors.
func (t *GoGitTransport) ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error) {
	auth, err := t.authFor(ctx, target, authRef)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	repo, err := t.openOrClone(ctx, target, auth)
	if err != nil {
		return ManifestSnapshot{}, fmt.Errorf("open or clone %s: %w", remoteURL(target), err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return ManifestSnapshot{}, fmt.Errorf("worktree: %w", err)
	}
	if pullErr := worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(target.Branch),
		Force:         true,
		Auth:          auth,
	}); pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return ManifestSnapshot{}, fmt.Errorf("fetch %s: %w", remoteURL(target), pullErr)
	}
	head, err := repo.Head()
	if err != nil {
		return ManifestSnapshot{}, fmt.Errorf("head: %w", err)
	}
	content, err := readFileAtHead(repo, target.Path)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	return ManifestSnapshot{Target: target, Content: content, Commit: head.Hash().String()}, nil
}

// readFileAtHead resolves a path in the head tree. Missing paths are the
// documented new-file vacancy: ErrNotFound, not a hard failure.
func readFileAtHead(repo *git.Repository, path string) ([]byte, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("tree: %w", err)
	}
	file, err := tree.File(path)
	if err != nil {
		return nil, ErrNotFound
	}
	content, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("file reader: %w", err)
	}
	defer func() {
		if closeErr := content.Close(); closeErr != nil {
			err = fmt.Errorf("close file reader: %w", closeErr)
		}
	}()
	return io.ReadAll(content)
}

// DryRun returns the before/after diff without remote-side effects.
// The transport fetches the live head, rejects a stale BaseCommit, and
// never writes.
func (t *GoGitTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	auth, err := t.authFor(ctx, change.Target, authRef)
	if err != nil {
		return Diff{}, err
	}
	repo, err := t.openOrClone(ctx, change.Target, auth)
	if err != nil {
		return Diff{}, fmt.Errorf("open or clone %s: %w", remoteURL(change.Target), err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return Diff{}, fmt.Errorf("worktree: %w", err)
	}
	if pullErr := worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(change.Target.Branch),
		Force:         true,
		Auth:          auth,
	}); pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return Diff{}, fmt.Errorf("fetch %s: %w", remoteURL(change.Target), pullErr)
	}
	head, err := repo.Head()
	if err != nil {
		return Diff{}, fmt.Errorf("head: %w", err)
	}
	// Stale base check: the caller edited an obsolete revision.
	if change.BaseCommit != "" && head.Hash().String() != change.BaseCommit {
		return Diff{}, &BaseCommitError{Expected: change.BaseCommit, Actual: head.Hash().String()}
	}
	before, err := readFileAtHead(repo, change.Target.Path)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Diff{}, err
	}
	return Diff{Target: change.Target, BaseCommit: change.BaseCommit, Before: before, After: append([]byte(nil), change.Content...)}, nil
}

// PushBranch commits the change and pushes to the target branch (or the
// change branch for proposals). The push is a plain, non-forcing push:
// when the remote moved, go-git rejects it and the transport maps that to
// ConflictError so the handler returns 409 immediately.
func (t *GoGitTransport) PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error) {
	auth, err := t.authFor(ctx, change.Target, authRef)
	if err != nil {
		return PushResult{}, err
	}
	repo, err := t.openOrClone(ctx, change.Target, auth)
	if err != nil {
		return PushResult{}, fmt.Errorf("open or clone %s: %w", remoteURL(change.Target), err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return PushResult{}, fmt.Errorf("worktree: %w", err)
	}
	if pullErr := worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(change.Target.Branch),
		Force:         true,
		Auth:          auth,
	}); pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return PushResult{}, fmt.Errorf("fetch %s: %w", remoteURL(change.Target), pullErr)
	}
	head, err := repo.Head()
	if err != nil {
		return PushResult{}, fmt.Errorf("head: %w", err)
	}
	// Stale base guard before any write: never build on an obsolete base.
	if change.BaseCommit != "" && head.Hash().String() != change.BaseCommit {
		return PushResult{}, &ConflictError{Expected: change.BaseCommit, Actual: head.Hash().String()}
	}

	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}

	// Idempotent same-content short-circuit: when the file already has the
	// requested content at head, the change is already delivered.
	if existing, readErr := readFileAtHead(repo, change.Target.Path); readErr == nil && bytes.Equal(existing, change.Content) {
		return PushResult{Repository: change.Target.Repository, Branch: branch, Commit: head.Hash().String()}, nil
	}

	// Write the file into the worktree and commit. Missing parent
	// directories are created for the new-file vacancy case.
	fullPath := filepath.Join(worktree.Filesystem.Root(), change.Target.Path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o700); err != nil {
		return PushResult{}, fmt.Errorf("create parent dirs: %w", err)
	}
	if err := os.WriteFile(fullPath, change.Content, 0o600); err != nil {
		return PushResult{}, fmt.Errorf("write file: %w", err)
	}
	if _, err := worktree.Add(change.Target.Path); err != nil {
		return PushResult{}, fmt.Errorf("add: %w", err)
	}
	commitHash, err := worktree.Commit(change.commitMessage(), &git.CommitOptions{
		Author: &object.Signature{
			Name:  t.authorName,
			Email: t.authorEmail,
			When:  t.now(),
		},
		AllowEmptyCommits: false,
	})
	if err != nil {
		return PushResult{}, fmt.Errorf("commit: %w", err)
	}
	// Proposal pushes go to a dedicated branch; direct pushes to the
	// mapped branch. The refspec is a plain non-forcing push.
	if err := repo.PushContext(ctx, &git.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/" + branch + ":refs/heads/" + branch)},
		Auth:       auth,
	}); err != nil {
		return PushResult{}, t.mapPushError(err, change)
	}
	return PushResult{Repository: change.Target.Repository, Branch: branch, Commit: commitHash.String()}, nil
}

func (c Change) commitMessage() string {
	return "kubeseal-ui: update " + c.Target.Path
}

// mapPushError converts go-git push failures to contract errors. A
// non-fast-forward rejection is a ConflictError; everything else is a
// transport failure the handler maps to 502.
func (t *GoGitTransport) mapPushError(err error, change Change) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil
	}
	if errors.Is(err, git.ErrNonFastForwardUpdate) {
		return &ConflictError{Expected: change.BaseCommit, Actual: "remote moved"}
	}
	return fmt.Errorf("push %s: %w", remoteURL(change.Target), err)
}
