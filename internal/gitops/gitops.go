// Package gitops defines platform-neutral Git delivery contracts.
package gitops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"sigs.k8s.io/yaml"
)

type Target struct {
	Repository string
	Branch     string
	Path       string
}

type ManifestSnapshot struct {
	Target  Target
	Content []byte
	Commit  string
}

// Change describes an edit based on BaseCommit. Branch is optional; when empty, the target
// branch is used. Implementations must never force-push a change.
type Change struct {
	Target     Target
	BaseCommit string
	Content    []byte
	Branch     string
}

// Diff is the result of a dry run; it has no remote-side effects.
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

type ProposalRequest struct {
	Change Change
	Push   PushResult
	Title  string
	Body   string
}

type ProposalResult struct {
	URL        string
	Repository string
	Branch     string
	Commit     string
}

// GitTransport performs portable Git operations. It has no host-provider API. authRef selects
// the typed credential for the target repository; the resolver resolves it server-side. An
// empty authRef is valid only for remotes that need no credentials.
type GitTransport interface {
	ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error)
	SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error)
	DryRun(ctx context.Context, change Change, authRef string) (Diff, error)
	PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error)
}

// ManifestHistory is the optional capability answering what a mapped file held before its most
// recent change. Drift reports only that the live Secret and the file differ; comparing the live
// Secret with this version is what tells the two apart — a match means Git moved and the cluster
// did not, so overwriting the file would discard the change that moved it.
type ManifestHistory interface {
	PreviousManifest(ctx context.Context, target Target, authRef string) ([]byte, error)
}

// ProposalProvider creates a host-specific review object for an already pushed branch.
type ProposalProvider interface {
	OpenProposal(context.Context, ProposalRequest) (ProposalResult, error)
}

type BaseCommitError struct{ Expected, Actual string }

func (e *BaseCommitError) Error() string {
	return fmt.Sprintf("base commit mismatch: expected %q, actual %q", e.Expected, e.Actual)
}

type ConflictError struct{ Expected, Actual string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("push conflict: expected %q, actual %q", e.Expected, e.Actual)
}

var ErrNotFound = errors.New("git target not found")

// ErrNoHistory means nothing precedes the current version of the target: the file has no earlier
// content, or the transport cannot read history at all.
var ErrNoHistory = errors.New("git target has no previous version")

type localEntry struct {
	content []byte
	commit  string
	// previous is what content replaced, which is what PreviousManifest answers with.
	previous []byte
}

// branchKey identifies a branch head independently of any file.
func branchKey(repository, branch string) string {
	return repository + "\x00" + branch
}

// LocalTransport is a concurrency-safe in-memory transport for contract tests.
type LocalTransport struct {
	mu      sync.RWMutex
	entries map[Target]localEntry
	// heads tracks a branch head per repository+branch, which is what a BaseCommit is compared
	// against. Without it there would be no way to report a base commit for a file that does
	// not exist yet, and mock mode could not exercise the new-secret flow at all.
	heads map[string]string
}

func NewLocalTransport() *LocalTransport {
	return &LocalTransport{entries: make(map[Target]localEntry), heads: make(map[string]string)}
}

// Seed initializes a target; seeding a file also moves its branch head to that commit,
// standing in for the real remote's head. A re-seed keeps the superseded content as the
// previous version.
func (t *LocalTransport) Seed(target Target, content, commit string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(target, []byte(content), commit)
	t.heads[branchKey(target.Repository, target.Branch)] = commit
}

// put records content at target, holding on to what the path held as its previous version.
// Callers hold the lock.
func (t *LocalTransport) put(target Target, content []byte, commit string) {
	entry := localEntry{content: append([]byte(nil), content...), commit: commit}
	if prior, ok := t.entries[target]; ok {
		if bytes.Equal(prior.content, content) {
			// Rewriting the same content is not a new version.
			entry.previous = prior.previous
		} else {
			entry.previous = prior.content
		}
	}
	t.entries[target] = entry
}

var _ ManifestHistory = (*LocalTransport)(nil)

// PreviousManifest returns the content the target held before its most recent change.
func (t *LocalTransport) PreviousManifest(_ context.Context, target Target, _ string) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	entry, ok := t.entries[target]
	if !ok || entry.previous == nil {
		return nil, ErrNoHistory
	}
	return append([]byte(nil), entry.previous...), nil
}

// ReadManifest returns the entry at target. A vacant path is ErrNotFound.
//
// The error path is not a zero snapshot: it carries the branch head, which is the value a new
// file is built on and the value a later BaseCommit check compares against. A branch nothing
// has been seeded on has no head, so the commit is empty — the new-secret flow surfaces that
// rather than sending an empty base commit to endpoints that reject it.
func (t *LocalTransport) ReadManifest(_ context.Context, target Target, _ string) (ManifestSnapshot, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.entries[target]
	if !ok {
		return ManifestSnapshot{Target: target, Commit: t.heads[branchKey(target.Repository, target.Branch)]}, ErrNotFound
	}
	return ManifestSnapshot{target, append([]byte(nil), e.content...), e.commit}, nil
}

type partialSealedSecret struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Spec struct {
		Template struct {
			Metadata struct {
				Namespace string `yaml:"namespace"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// identityKey is how a SealedSecret is looked up. The separator cannot occur in a Kubernetes name,
// so no (namespace, name) pair collides with another.
func identityKey(namespace, name string) string { return namespace + "\x00" + name }

// sealedSecretIdentities returns the identity of every SealedSecret document in content. One parser
// serves both the single-content match and the branch search index, so a file a search matches is
// indexed under exactly the identity that search would have matched.
func sealedSecretIdentities(content []byte) []string {
	var identities []string
	for _, docBytes := range bytes.Split(content, []byte("\n---")) {
		var doc partialSealedSecret
		if err := yaml.Unmarshal(docBytes, &doc); err != nil {
			continue
		}
		if doc.Kind != "SealedSecret" {
			continue
		}
		namespace := doc.Metadata.Namespace
		if namespace == "" {
			namespace = doc.Spec.Template.Metadata.Namespace
		}
		identities = append(identities, identityKey(namespace, doc.Metadata.Name))
	}
	return identities
}

// MatchesSealedSecret reports whether raw YAML content (single or multi-doc) holds a
// SealedSecret matching the given name and namespace. A manifest that names no namespace is matched
// by name alone, whatever namespace the caller asked about.
func MatchesSealedSecret(content []byte, namespace, name string) bool {
	for _, identity := range sealedSecretIdentities(content) {
		if identity == identityKey(namespace, name) || identity == identityKey("", name) {
			return true
		}
	}
	return false
}

// lookupIdentity resolves an identity against an index of identityKey to path, applying the same
// rule MatchesSealedSecret applies to content: the identity asked for, or a manifest that names no
// namespace and so matches by name alone. Both are answers, and the one that names the namespace is
// preferred — it is the one certainly about the identity that was asked for.
func lookupIdentity(index map[string]string, namespace, name string) (string, bool) {
	if path, ok := index[identityKey(namespace, name)]; ok {
		return path, true
	}
	path, ok := index[identityKey("", name)]
	return path, ok
}

func (t *LocalTransport) SearchManifest(_ context.Context, repository, branch, namespace, name, _ string) (ManifestSnapshot, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for target, entry := range t.entries {
		if target.Repository != repository || target.Branch != branch {
			continue
		}
		if MatchesSealedSecret(entry.content, namespace, name) {
			return ManifestSnapshot{Target: target, Content: append([]byte(nil), entry.content...), Commit: entry.commit}, nil
		}
	}
	return ManifestSnapshot{}, ErrNotFound
}
func (t *LocalTransport) DryRun(ctx context.Context, change Change, _ string) (Diff, error) {
	s, err := t.ReadManifest(ctx, change.Target, "")
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
func (t *LocalTransport) PushBranch(_ context.Context, change Change, _ string) (PushResult, error) {
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}
	target := change.Target
	target.Branch = branch
	t.mu.Lock()
	defer t.mu.Unlock()
	// BaseCommit is checked against the head of the branch being built on, not against the
	// file's own last commit. The two differ in exactly the new-file case: the file has no
	// commit yet, and the change is legitimately built on the current head.
	head := t.heads[branchKey(change.Target.Repository, change.Target.Branch)]
	if change.BaseCommit != "" && change.BaseCommit != head {
		return PushResult{}, &ConflictError{change.BaseCommit, head}
	}
	commitHash := sha256.Sum256(append([]byte(change.BaseCommit+"\x00"), change.Content...))
	commit := hex.EncodeToString(commitHash[:])
	t.put(target, change.Content, commit)
	t.heads[branchKey(target.Repository, branch)] = commit
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
