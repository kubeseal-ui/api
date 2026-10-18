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

// Change describes an edit built on BaseCommit; implementations must never force-push.
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

// GitTransport performs portable Git operations; authRef selects the typed credential server-side.
type GitTransport interface {
	ReadManifest(ctx context.Context, target Target, authRef string) (ManifestSnapshot, error)
	SearchManifest(ctx context.Context, repository, branch, namespace, name, authRef string) (ManifestSnapshot, error)
	DryRun(ctx context.Context, change Change, authRef string) (Diff, error)
	PushBranch(ctx context.Context, change Change, authRef string) (PushResult, error)
}

// ManifestHistory answers what a mapped file held before its last change; a live match against it means Git moved and the cluster did not.
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

// ErrNoHistory reports no earlier content, or a transport that cannot read history at all.
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
	// heads tracks branch heads, the values BaseCommit is compared against — including for files that do not exist yet.
	heads map[string]string
}

func NewLocalTransport() *LocalTransport {
	return &LocalTransport{entries: make(map[Target]localEntry), heads: make(map[string]string)}
}

// Seed initializes a target and moves its branch head; a re-seed keeps the superseded content as the previous version.
func (t *LocalTransport) Seed(target Target, content, commit string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.put(target, []byte(content), commit)
	t.heads[branchKey(target.Repository, target.Branch)] = commit
}

// put records content at target, holding what the path held as its previous version; callers hold the lock.
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

// ReadManifest returns ErrNotFound for a vacant path; the error snapshot still carries the branch head a new file is built on.
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

// identityKey is the lookup key; the separator cannot occur in a Kubernetes name, so no pair collides.
func identityKey(namespace, name string) string { return namespace + "\x00" + name }

// sealedSecretIdentity reports the lookup key of one YAML document; false when it is not a SealedSecret.
func sealedSecretIdentity(doc []byte) (string, bool) {
	var parsed partialSealedSecret
	if err := yaml.Unmarshal(doc, &parsed); err != nil {
		return "", false
	}
	if parsed.Kind != "SealedSecret" {
		return "", false
	}
	namespace := parsed.Metadata.Namespace
	if namespace == "" {
		namespace = parsed.Spec.Template.Metadata.Namespace
	}
	return identityKey(namespace, parsed.Metadata.Name), true
}

// splitYAMLDocuments splits on bare `---` lines, keeping each separator with the document that
// follows, so bytes.Join of the parts reproduces the input byte for byte.
func splitYAMLDocuments(content []byte) [][]byte {
	var docs [][]byte
	var current []byte
	for _, line := range bytes.SplitAfter(content, []byte("\n")) {
		if len(current) > 0 && bytes.Equal(bytes.TrimSpace(line), []byte("---")) {
			docs = append(docs, current)
			current = nil
		}
		current = append(current, line...)
	}
	if len(current) > 0 {
		docs = append(docs, current)
	}
	return docs
}

// sealedSecretIdentities indexes every SealedSecret doc, so a search hit and a content match use one parser.
func sealedSecretIdentities(content []byte) []string {
	var identities []string
	for _, doc := range splitYAMLDocuments(content) {
		if key, ok := sealedSecretIdentity(doc); ok {
			identities = append(identities, key)
		}
	}
	return identities
}

// MatchesSealedSecret reports multi-doc content holding a matching SealedSecret; a manifest naming no namespace matches by name alone.
func MatchesSealedSecret(content []byte, namespace, name string) bool {
	for _, identity := range sealedSecretIdentities(content) {
		if identity == identityKey(namespace, name) || identity == identityKey("", name) {
			return true
		}
	}
	return false
}

// SpliceSealedSecret replaces the document matching namespace/name inside a multi-document file,
// leaving every sibling byte for byte identical; false means nothing matched and `incoming` is the
// whole file. The destination lookup guarantees a match before this is called — false is a race,
// and the caller falls back to whole-file content only because the base-commit guard still stands.
func SpliceSealedSecret(existing, incoming []byte, namespace, name string) ([]byte, bool) {
	docs := splitYAMLDocuments(existing)
	for i, doc := range docs {
		if key, ok := sealedSecretIdentity(doc); ok && (key == identityKey(namespace, name) || key == identityKey("", name)) {
			if !bytes.HasSuffix(incoming, []byte("\n")) {
				incoming = append(incoming, '\n')
			}
			docs[i] = incoming
			return bytes.Join(docs, nil), true
		}
	}
	return incoming, false
}

// lookupIdentity prefers the namespace-specific hit over a manifest that names no namespace.
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
	// BaseCommit is checked against the branch head, not the file's last commit — the two differ exactly in the new-file case.
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
