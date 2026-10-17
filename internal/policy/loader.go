// Loading the policy document from disk and re-reading it on demand. The read is explicit (SIGHUP), because a
// ConfigMap symlink swap makes file watches fire on a path already replaced; a failed reload keeps the last valid generation.
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

// NewLoader reads path and applies it; at boot there is no previous generation to fall back on, so any failure refuses to start.
func NewLoader(path string, store *PolicyStore) (*Loader, error) {
	loader := &Loader{path: path, store: store}
	if err := loader.Reload(); err != nil {
		return nil, err
	}
	return loader, nil
}

// Reload re-reads the file and swaps the store's generation; on failure the store keeps its previous one.
func (l *Loader) Reload() error {
	err := l.apply()
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
	return err
}

// Err reports the most recent reload failure, or nil once a reload succeeds; readiness consults it.
func (l *Loader) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

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
		// Present but unread; saying so keeps an operator from discovering the git half is inert from a misdirected delivery.
		slog.Warn("policy document has a git section, which this api does not read; namespace mappings come from GITOPS_NAMESPACES",
			"path", l.path)
	}
	return l.store.Apply(doc)
}

// hasContent reports whether a decoded section carries anything; absent, null, and empty all mean the section said nothing.
func hasContent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte("{}"))
}
