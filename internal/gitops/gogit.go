// go-git implementation of the GitTransport contract; never force-pushes, resets, rebases, or retries —
// a conflicting push surfaces ConflictError for the handler's 409.
package gitops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// GoGitTransport performs real Git operations through go-git. The worktree is per-target under
// a scratch directory, and fetch is repeated per call so live remote state is always observed.
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
	// worktrees serialises the operations sharing one checkout directory; one transport serves the whole process.
	worktrees worktreeLocks
}

type GoGitOptions struct {
	// ScratchDir holds per-target worktrees. Defaults to os.TempDir()/kubeseal-ui-gitops.
	ScratchDir string
	// AuthorName stamps delivery commits. Defaults to "kubeseal-ui".
	AuthorName string
	// AuthorEmail stamps delivery commits.
	AuthorEmail string
	// Credentials resolves typed auth; may be nil for open remotes.
	Credentials CredentialResolver
}

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

// worktreePath derives a per-repository+branch directory; the sanitized name is not injective, so the
// raw pair's digest keeps two different branches out of one checkout.
func (t *GoGitTransport) worktreePath(target Target) string {
	return t.checkoutPath(target, "worktree")
}

// checkoutPath builds the directory for one kind of checkout; kind is its own path component so no branch name can collide with it.
func (t *GoGitTransport) checkoutPath(target Target, kind string) string {
	safe := func(value string) string {
		replaced := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
				return r
			}
			return '_'
		}, value)
		return replaced
	}
	digest := sha256.Sum256([]byte(target.Repository + "\x00" + target.Branch))
	return filepath.Join(t.scratch, kind, safe(target.Repository), safe(target.Branch)+"-"+hex.EncodeToString(digest[:8]))
}

// authFor resolves credentials for a target; a resolver miss is an error, never an implicit anonymous push.
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

// openOrClone returns the repository worktree at path, cloning when there is no checkout yet; depth limits a fresh clone (0 = full history).
func (t *GoGitTransport) openOrClone(ctx context.Context, path string, target Target, auth transport.AuthMethod, depth int) (*git.Repository, error) {
	if _, statErr := os.Stat(path); statErr == nil {
		if repo, openErr := git.PlainOpen(path); openErr == nil {
			return repo, nil
		}
		// A broken scratch entry is re-cloned, not trusted.
		if removeErr := os.RemoveAll(path); removeErr != nil {
			return nil, fmt.Errorf("reset broken worktree %s: %w", path, removeErr)
		}
	}
	return git.PlainCloneContext(ctx, path, false, &git.CloneOptions{
		URL:           remoteURL(target),
		ReferenceName: plumbing.NewBranchReferenceName(target.Branch),
		SingleBranch:  true,
		Depth:         depth,
		Auth:          auth,
	})
}

// historyPath is a second checkout of the same repository+branch for PreviousManifest, which needs
// commits behind the head that the depth-1 read worktree does not carry.
func (t *GoGitTransport) historyPath(target Target) string {
	return t.checkoutPath(target, "history")
}

func remoteURL(target Target) string {
	if strings.Contains(target.Repository, "://") || strings.Contains(target.Repository, "@") {
		return target.Repository
	}
	repo := strings.TrimSuffix(target.Repository, ".git")
	if strings.HasPrefix(repo, "github.com/") {
		return "https://" + repo + ".git"
	}
	if strings.Count(repo, "/") == 1 {
		return "https://github.com/" + repo + ".git"
	}
	return "https://" + repo + ".git"
}

// ReadManifest fetches the remote and reads the file at a target. A vacant path returns ErrNotFound,
// but the snapshot still carries the branch head the new file must be built on.
func (t *GoGitTransport) ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error) {
	auth, err := t.authFor(ctx, target, authRef)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	path := t.worktreePath(target)
	release, err := t.worktrees.lock(ctx, path)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	defer release()
	repo, err := t.openOrClone(ctx, path, target, auth, 1)
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
		// Vacant path: still report the branch head for the caller to build on.
		if errors.Is(err, ErrNotFound) {
			return ManifestSnapshot{Target: target, Commit: head.Hash().String()}, ErrNotFound
		}
		return ManifestSnapshot{}, err
	}
	return ManifestSnapshot{Target: target, Content: content, Commit: head.Hash().String()}, nil
}

// readFileAtHead resolves a path in the head tree; a missing path is the documented new-file vacancy.
func readFileAtHead(repo *git.Repository, path string) ([]byte, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return fileAtCommit(commit, path)
}

// fileAtCommit reads one path out of one commit's tree; a path the commit does not hold is ErrNotFound.
func fileAtCommit(commit *object.Commit, path string) ([]byte, error) {
	file, err := commit.File(path)
	if err != nil {
		if errors.Is(err, object.ErrFileNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("tree: %w", err)
	}
	return readBlob(file)
}

// Compile-time assertion: a silent signature drift here would make the detail page stop answering
// whether Git moved ahead, and go back to offering a sync that overwrites the change.
var _ ManifestHistory = (*GoGitTransport)(nil)

// PreviousManifest reads the version the file held before the most recent commit that changed it; it
// needs its own full-history checkout because go-git cannot deepen a shallow clone. ErrNoHistory when
// nothing precedes the current version.
func (t *GoGitTransport) PreviousManifest(ctx context.Context, target Target, authRef string) ([]byte, error) {
	auth, err := t.authFor(ctx, target, authRef)
	if err != nil {
		return nil, err
	}
	// The history checkout is a directory of its own, so it has a lock of its own.
	path := t.historyPath(target)
	release, err := t.worktrees.lock(ctx, path)
	if err != nil {
		return nil, err
	}
	defer release()
	repo, err := t.openOrClone(ctx, path, target, auth, 0)
	if err != nil {
		return nil, fmt.Errorf("open or clone %s: %w", remoteURL(target), err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("worktree: %w", err)
	}
	if pullErr := worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(target.Branch),
		Force:         true,
		Auth:          auth,
	}); pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("fetch %s: %w", remoteURL(target), pullErr)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	// The newest commit whose diff against its parent touches the path; the version before it is
	// the one sitting in that parent's tree.
	iter, err := repo.Log(&git.LogOptions{
		From:     head.Hash(),
		Order:    git.LogOrderCommitterTime,
		FileName: &target.Path,
	})
	if err != nil {
		return nil, fmt.Errorf("log %s: %w", target.Path, err)
	}
	defer iter.Close()
	changed, err := iter.Next()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrNoHistory
		}
		return nil, fmt.Errorf("log %s: %w", target.Path, err)
	}
	parent, err := changed.Parent(0)
	if err != nil {
		// The commit that changed the path is the root: nothing precedes it.
		return nil, ErrNoHistory
	}
	previous, err := fileAtCommit(parent, target.Path)
	if errors.Is(err, ErrNotFound) {
		// That commit created the file, so no version precedes this one.
		return nil, ErrNoHistory
	}
	return previous, err
}

// Compile-time assertion: a silent signature drift here would make SnapshotTransport stop recognizing
// the transport, and the listing quietly go back to one pull per Secret.
var _ BranchReader = (*GoGitTransport)(nil)

// ReadBranch fetches the remote once and returns every file at the branch head, so a listing resolves
// drift for all its Secrets with one fetch. Every blob at head is read, not only expected paths, and a
// blob that cannot be read fails the whole snapshot — a skip would turn "exists" into "vacant".
func (t *GoGitTransport) ReadBranch(ctx context.Context, repository, branch, authRef string) (BranchSnapshot, error) {
	target := Target{Repository: repository, Branch: branch}
	auth, err := t.authFor(ctx, target, authRef)
	if err != nil {
		return BranchSnapshot{}, err
	}
	path := t.worktreePath(target)
	release, err := t.worktrees.lock(ctx, path)
	if err != nil {
		return BranchSnapshot{}, err
	}
	defer release()
	repo, err := t.openOrClone(ctx, path, target, auth, 1)
	if err != nil {
		return BranchSnapshot{}, fmt.Errorf("open or clone %s: %w", remoteURL(target), err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		return BranchSnapshot{}, fmt.Errorf("worktree: %w", err)
	}
	if pullErr := worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(target.Branch),
		Force:         true,
		Auth:          auth,
	}); pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return BranchSnapshot{}, fmt.Errorf("fetch %s: %w", remoteURL(target), pullErr)
	}
	head, err := repo.Head()
	if err != nil {
		return BranchSnapshot{}, fmt.Errorf("head: %w", err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return BranchSnapshot{}, fmt.Errorf("commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return BranchSnapshot{}, fmt.Errorf("tree: %w", err)
	}

	files := map[string][]byte{}
	fileIter := tree.Files()
	defer fileIter.Close()
	if err := fileIter.ForEach(func(f *object.File) error {
		content, readErr := readBlob(f)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", f.Name, readErr)
		}
		files[f.Name] = content
		return nil
	}); err != nil {
		return BranchSnapshot{}, err
	}
	return BranchSnapshot{Commit: head.Hash().String(), Files: files}, nil
}

// readBlob reads one file's content at head.
func readBlob(file *object.File) ([]byte, error) {
	reader, err := file.Reader()
	if err != nil {
		return nil, fmt.Errorf("blob reader: %w", err)
	}
	content, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	return content, nil
}

// SearchManifest walks the tree at head for a SealedSecret matching the identity. Duplicate identities
// resolve to whichever file the iterator reaches first — deterministic, but not a chosen rule; the write
// path refuses occupied templated paths rather than this read resolving them.
func (t *GoGitTransport) SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error) {
	target := Target{Repository: repository, Branch: branch}
	auth, err := t.authFor(ctx, target, authRef)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	path := t.worktreePath(target)
	release, err := t.worktrees.lock(ctx, path)
	if err != nil {
		return ManifestSnapshot{}, err
	}
	defer release()
	repo, err := t.openOrClone(ctx, path, target, auth, 1)
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
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return ManifestSnapshot{}, fmt.Errorf("commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return ManifestSnapshot{}, fmt.Errorf("tree: %w", err)
	}

	fileIter := tree.Files()
	defer fileIter.Close()

	var matchedSnapshot ManifestSnapshot
	var matched bool
	// A blob that cannot be read is not a blob that does not match: keep errors and report them with the not-found answer.
	var readErrs []error

	err = fileIter.ForEach(func(f *object.File) error {
		if matched {
			return nil
		}
		if !strings.HasSuffix(f.Name, ".yaml") && !strings.HasSuffix(f.Name, ".yml") {
			return nil
		}
		rc, openErr := f.Reader()
		if openErr != nil {
			readErrs = append(readErrs, fmt.Errorf("open %s: %w", f.Name, openErr))
			return nil
		}
		content, readErr := io.ReadAll(rc)
		if closeErr := rc.Close(); closeErr != nil || readErr != nil {
			readErrs = append(readErrs, fmt.Errorf("read %s: %w", f.Name, errors.Join(readErr, closeErr)))
			return nil
		}
		if MatchesSealedSecret(content, namespace, name) {
			matchedSnapshot = ManifestSnapshot{
				Target:  Target{Repository: repository, Branch: branch, Path: f.Name},
				Content: content,
				Commit:  head.Hash().String(),
			}
			matched = true
		}
		return nil
	})
	if err != nil {
		return ManifestSnapshot{}, err
	}
	if !matched {
		if len(readErrs) > 0 {
			return ManifestSnapshot{}, errors.Join(append([]error{ErrNotFound}, readErrs...)...)
		}
		return ManifestSnapshot{}, ErrNotFound
	}
	return matchedSnapshot, nil
}

// DryRun returns the before/after diff without remote-side effects, rejecting a stale BaseCommit.
func (t *GoGitTransport) DryRun(ctx context.Context, change Change, authRef string) (Diff, error) {
	auth, err := t.authFor(ctx, change.Target, authRef)
	if err != nil {
		return Diff{}, err
	}
	path := t.worktreePath(change.Target)
	release, err := t.worktrees.lock(ctx, path)
	if err != nil {
		return Diff{}, err
	}
	defer release()
	repo, err := t.openOrClone(ctx, path, change.Target, auth, 1)
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
	if change.BaseCommit != "" && head.Hash().String() != change.BaseCommit {
		return Diff{}, &BaseCommitError{Expected: change.BaseCommit, Actual: head.Hash().String()}
	}
	before, err := readFileAtHead(repo, change.Target.Path)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Diff{}, err
	}
	return Diff{Target: change.Target, BaseCommit: change.BaseCommit, Before: before, After: append([]byte(nil), change.Content...)}, nil
}

// PushBranch commits the change and pushes to the target branch (or the change branch for proposals);
// the push is plain and non-forcing, so a remote that moved maps to ConflictError.
func (t *GoGitTransport) PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error) {
	auth, err := t.authFor(ctx, change.Target, authRef)
	if err != nil {
		return PushResult{}, err
	}
	// Held across the whole read-modify-write: pull, add, commit and push share one index and one HEAD.
	path := t.worktreePath(change.Target)
	release, err := t.worktrees.lock(ctx, path)
	if err != nil {
		return PushResult{}, err
	}
	defer release()
	repo, err := t.openOrClone(ctx, path, change.Target, auth, 1)
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
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}

	// A proposal pushes a branch that does not exist locally; without this ref go-git returns
	// NoErrAlreadyUpToDate — success for a push that never happened. Shared with the short-circuit
	// below, which returns before the commit exists.
	//
	// NoErrAlreadyUpToDate is not a failure: the commit is on the remote either way.
	deliver := func(commit plumbing.Hash) (PushResult, error) {
		if branch != change.Target.Branch {
			refErr := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), commit))
			if refErr != nil {
				return PushResult{}, fmt.Errorf("create proposal ref %s: %w", branch, refErr)
			}
		}
		// The refspec is a plain non-forcing push.
		pushErr := repo.PushContext(ctx, &git.PushOptions{
			RemoteName: "origin",
			RefSpecs:   []config.RefSpec{config.RefSpec("refs/heads/" + branch + ":refs/heads/" + branch)},
			Auth:       auth,
		})
		if mapped := t.mapPushError(pushErr, change); mapped != nil {
			return PushResult{}, mapped
		}
		return PushResult{Repository: change.Target.Repository, Branch: branch, Commit: commit.String()}, nil
	}

	// Same-content short-circuit before the stale-base guard: a retry of a landed push must not become
	// a conflict against the base that push moved. The push still runs so the proposal branch exists.
	if existing, readErr := readFileAtHead(repo, change.Target.Path); readErr == nil && bytes.Equal(existing, change.Content) {
		return deliver(head.Hash())
	}

	// Stale base guard before any write: never build on an obsolete base.
	if change.BaseCommit != "" && head.Hash().String() != change.BaseCommit {
		return PushResult{}, &ConflictError{Expected: change.BaseCommit, Actual: head.Hash().String()}
	}

	// Parent directories are created for the new-file vacancy case.
	fullPath := filepath.Join(worktree.Filesystem.Root(), change.Target.Path)
	if mkdirErr := os.MkdirAll(filepath.Dir(fullPath), 0o700); mkdirErr != nil {
		return PushResult{}, fmt.Errorf("create parent dirs: %w", mkdirErr)
	}
	if writeErr := os.WriteFile(fullPath, change.Content, 0o600); writeErr != nil {
		return PushResult{}, fmt.Errorf("write file: %w", writeErr)
	}
	if _, addErr := worktree.Add(change.Target.Path); addErr != nil {
		return PushResult{}, fmt.Errorf("add: %w", addErr)
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
	return deliver(commitHash)
}

func (c Change) commitMessage() string {
	return "kubeseal-ui: update " + c.Target.Path
}

// mapPushError converts go-git push failures: a non-fast-forward rejection is a ConflictError, the rest a transport failure (502).
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
