// Reading the policy document from disk, and re-reading it on demand.
//
// The read is explicit rather than watched. A ConfigMap is projected into a pod
// as a symlink swap, so a file watch fires on a path that has already been
// replaced, and the api already has a signal for "re-read your configuration"
// in SIGHUP. Reloading is therefore something an operator asks for, and the
// answer to a bad request is to keep the generation that was already valid:
// falling back to no policy would replace a working grant set with a lockout at
// the exact moment someone was already fixing the file.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// Loader keeps a store's authorization generation in step with a file.
type Loader struct {
	path  string
	store *PolicyStore

	mu  sync.Mutex
	err error // the most recent reload failure; nil once a reload succeeds
}

// NewLoader reads path, applies it, and returns a loader that can re-read it.
//
// A document that cannot be read or fails validation is returned as an error
// rather than tolerated: at boot there is no previous generation to fall back
// on, so refusing to start is the only answer that does not serve a policy the
// operator did not write.
func NewLoader(path string, store *PolicyStore) (*Loader, error) {
	loader := &Loader{path: path, store: store}
	if err := loader.Reload(); err != nil {
		return nil, err
	}
	return loader, nil
}

// Reload re-reads the file and swaps the store's authorization generation.
//
// On failure the store keeps the generation it already had and Err reports the
// failure until a later reload succeeds.
func (l *Loader) Reload() error {
	err := l.apply()
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
	return err
}

// Err reports the most recent reload failure, or nil when the store holds the
// newest valid generation. Readiness consults it: a policy file that cannot be
// parsed is not a state to keep serving from without saying so.
func (l *Loader) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Path is the file this loader reads.
func (l *Loader) Path() string { return l.path }

func (l *Loader) apply() error {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return fmt.Errorf("read policy document: %w", err)
	}
	doc, err := ParseDocument(data)
	if err != nil {
		return fmt.Errorf("policy document %s: %w", l.path, err)
	}
	if hasContent(doc.Git) {
		// Present but unread. Saying so on every load is the difference between
		// an operator learning the git half is inert and discovering it from a
		// delivery that landed in the wrong repository.
		slog.Warn("policy document has a git section, which this api does not read; namespace mappings come from GITOPS_NAMESPACES",
			"path", l.path)
	}
	return l.store.Apply(doc)
}

// hasContent reports whether a decoded section carries anything. An absent key,
// an explicit null, and an empty mapping all mean the section said nothing.
func hasContent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("{}"))
}
