// Package gitops defines platform-neutral Git delivery contracts.
package gitops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// Target identifies a file on a repository branch.
type Target struct {
	Repository string
	Branch     string
	Path       string
}

// ManifestSnapshot is the content and commit observed at a target.
type ManifestSnapshot struct {
	Target  Target
	Content []byte
	Commit  string
}

// Change describes an edit based on BaseCommit. Branch is optional; when empty,
// the target branch is used. Implementations must never force-push a change.
type Change struct {
	Target     Target
	BaseCommit string
	Content    []byte
	Branch     string
}

// Diff is the result of a dry run. It contains no remote-side effects.
type Diff struct {
	Target     Target
	BaseCommit string
	Before     []byte
	After      []byte
}

// PushResult identifies the commit written by a non-forcing branch push.
type PushResult struct {
	Repository string
	Branch     string
	Commit     string
}

// ProposalRequest is the provider-neutral input after a branch was pushed.
type ProposalRequest struct {
	Change Change
	Push   PushResult
	Title  string
	Body   string
}

// ProposalResult identifies the host review object.
type ProposalResult struct {
	URL        string
	Repository string
	Branch     string
	Commit     string
}

// GitTransport performs portable Git operations. It has no host-provider API.
type GitTransport interface {
	ReadManifest(context.Context, Target) (ManifestSnapshot, error)
	DryRun(context.Context, Change) (Diff, error)
	PushBranch(context.Context, Change) (PushResult, error)
}

// ProposalProvider creates a host-specific review object for an already pushed branch.
type ProposalProvider interface {
	OpenProposal(context.Context, ProposalRequest) (ProposalResult, error)
}

// BaseCommitError indicates the caller edited an obsolete base.
type BaseCommitError struct{ Expected, Actual string }

func (e *BaseCommitError) Error() string {
	return fmt.Sprintf("base commit mismatch: expected %q, actual %q", e.Expected, e.Actual)
}

// ConflictError indicates a non-fast-forward/conflicting push.
type ConflictError struct{ Expected, Actual string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("push conflict: expected %q, actual %q", e.Expected, e.Actual)
}

var ErrNotFound = errors.New("git target not found")

type localEntry struct {
	content []byte
	commit  string
}

// LocalTransport is a concurrency-safe in-memory transport for contract tests.
type LocalTransport struct {
	mu      sync.RWMutex
	entries map[Target]localEntry
}

func NewLocalTransport() *LocalTransport {
	return &LocalTransport{entries: make(map[Target]localEntry)}
}

// Seed initializes a target, useful for tests.
func (t *LocalTransport) Seed(target Target, content, commit string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[target] = localEntry{[]byte(content), commit}
}
func (t *LocalTransport) ReadManifest(_ context.Context, target Target) (ManifestSnapshot, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[target]
	if !ok {
		return ManifestSnapshot{}, ErrNotFound
	}
	return ManifestSnapshot{target, append([]byte(nil), e.content...), e.commit}, nil
}
func (t *LocalTransport) DryRun(ctx context.Context, change Change) (Diff, error) {
	s, err := t.ReadManifest(ctx, change.Target)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Diff{}, err
	}
	if err == nil && s.Commit != change.BaseCommit {
		return Diff{}, &BaseCommitError{change.BaseCommit, s.Commit}
	}
	var before []byte
	if err == nil {
		before = s.Content
	}
	return Diff{change.Target, change.BaseCommit, before, append([]byte(nil), change.Content...)}, nil
}
func (t *LocalTransport) PushBranch(_ context.Context, change Change) (PushResult, error) {
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}
	target := change.Target
	target.Branch = branch
	t.mu.Lock()
	defer t.mu.Unlock()
	current, ok := t.entries[change.Target]
	if !ok && change.BaseCommit != "" {
		return PushResult{}, ErrNotFound
	}
	if ok && current.commit != change.BaseCommit {
		return PushResult{}, &ConflictError{change.BaseCommit, current.commit}
	}
	commitHash := sha256.Sum256(append([]byte(change.BaseCommit+"\x00"), change.Content...))
	commit := hex.EncodeToString(commitHash[:])
	t.entries[target] = localEntry{append([]byte(nil), change.Content...), commit}
	return PushResult{change.Target.Repository, branch, commit}, nil
}

// LocalProposalProvider is a deterministic provider-neutral test adapter.
type LocalProposalProvider struct{ URLPrefix string }

func (p LocalProposalProvider) OpenProposal(_ context.Context, request ProposalRequest) (ProposalResult, error) {
	if request.Push.Branch == "" || request.Push.Commit == "" {
		return ProposalResult{}, errors.New("proposal requires pushed branch and commit")
	}
	return ProposalResult{fmt.Sprintf("%s/%s/%s", p.URLPrefix, request.Push.Repository, request.Push.Branch), request.Push.Repository, request.Push.Branch, request.Push.Commit}, nil
}
