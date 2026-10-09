package handlers

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// How long a claimed Idempotency-Key is remembered, and the most that may be
// held at once.
//
// A key is remembered so a repeated submission is refused instead of executed
// twice, and nothing releases it when the request that claimed it finishes —
// outliving the request is the entire point. Left unbounded that is a leak: the
// store was a map that every diff, patch, deliver, and proposal call added a
// permanent entry to, and a long-lived pod could only grow. These two bounds
// are what make the memory finite.
//
// The TTL is the window in which a repeat counts as a double submit rather than
// as a fresh intent. The cap is the backstop for a burst arriving faster than
// the TTL drains it: past the cap the oldest claims are dropped, so sustained
// load forgets the earliest keys — the ones least likely to still be retried —
// rather than growing without limit.
const (
	idempotencyTTL     = 15 * time.Minute
	idempotencyMaxKeys = 4096
)

// idempotencyDecision is what the store has to say about a key.
type idempotencyDecision int

const (
	// idempotencyNew means the key was free, and is now claimed by this caller.
	idempotencyNew idempotencyDecision = iota
	// idempotencyInFlight means an identical request is still running.
	idempotencyInFlight
	// idempotencyReplay means an identical request already finished, and its
	// recorded response is returned so it can be replayed.
	idempotencyReplay
)

// idempotencyRecord is a completed response, kept so a retry can be answered
// with it rather than run again.
type idempotencyRecord struct {
	status int
	header http.Header
	body   []byte
}

type idempotencyEntry struct {
	expiry time.Time
	// done separates a request still running from one that finished and left a
	// record behind: the first is a double submit to refuse, the second a retry
	// to answer.
	done   bool
	record idempotencyRecord
}

// idempotencyStore records which (subject, key) pairs have been claimed.
//
// Insertion order is kept beside the map because both bounds are
// first-in-first-out, and a constant TTL makes expiry order identical to
// insertion order. That means the expired entries always form a prefix, so
// neither the sweep nor the cap ever has to look at an entry it is keeping.
//
// A key appears in order exactly once, which that prefix walk depends on:
// releasing a claim removes it from both, so re-claiming appends a fresh entry
// rather than leaving a stale one behind to be swept out from under it.
type idempotencyStore struct {
	mu      sync.Mutex
	entries map[string]*idempotencyEntry
	order   []string         // the same keys, oldest first
	now     func() time.Time // indirected so tests can move the clock
}

func newIdempotencyStore() *idempotencyStore {
	return &idempotencyStore{entries: make(map[string]*idempotencyEntry), now: time.Now}
}

// claim reports whether the caller may proceed, without recording a response.
// It is for endpoints that need only to refuse a duplicate; delivery endpoints
// use begin and finish instead, so a retry can be answered with the original
// outcome.
func (s *idempotencyStore) claim(key string) bool {
	decision, _ := s.begin(key)
	return decision == idempotencyNew
}

// begin claims a key and reports what the caller should do with it.
func (s *idempotencyStore) begin(key string) (idempotencyDecision, idempotencyRecord) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(now)
	if entry, ok := s.entries[key]; ok && entry.expiry.After(now) {
		if entry.done {
			return idempotencyReplay, entry.record
		}
		return idempotencyInFlight, idempotencyRecord{}
	}
	s.entries[key] = &idempotencyEntry{expiry: now.Add(idempotencyTTL)}
	s.order = append(s.order, key)
	s.evictLocked()
	return idempotencyNew, idempotencyRecord{}
}

// finish records the outcome of a claimed delivery.
//
// A success is remembered so a retry can be answered with the same commit. Any
// other status releases the claim instead, because a failure is not an outcome
// worth repeating: the caller should be free to try again, and a transient 502
// left holding the key would refuse every retry until it expired.
func (s *idempotencyStore) finish(key string, status int, header http.Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return // swept while the request was running; there is nothing to record on
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		s.releaseLocked(key)
		return
	}
	entry.done = true
	entry.record = idempotencyRecord{status: status, header: header, body: body}
}

// releaseLocked frees a claim so the key can be used again.
func (s *idempotencyStore) releaseLocked(key string) {
	delete(s.entries, key)
	for i, existing := range s.order {
		if existing == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

// sweepLocked drops expired entries from the front of the order.
func (s *idempotencyStore) sweepLocked(now time.Time) {
	drop := 0
	for drop < len(s.order) {
		entry, ok := s.entries[s.order[drop]]
		if ok && entry.expiry.After(now) {
			break
		}
		delete(s.entries, s.order[drop])
		drop++
	}
	if drop > 0 {
		s.order = append(s.order[:0], s.order[drop:]...)
	}
}

// evictLocked holds the store at the cap by dropping the oldest claims. It is
// the backstop the sweep cannot provide: a burst of distinct keys inside one
// TTL window is all live at once, so nothing there is expired to collect.
func (s *idempotencyStore) evictLocked() {
	if len(s.order) <= idempotencyMaxKeys {
		return
	}
	drop := len(s.order) - idempotencyMaxKeys
	for _, key := range s.order[:drop] {
		delete(s.entries, key)
	}
	s.order = append(s.order[:0], s.order[drop:]...)
}

// recordingResponseWriter captures a handler's response so a later retry can be
// answered with it.
//
// It writes through to the real writer as it goes: the response is not held
// back from the caller being served, only remembered for the next one, so the
// behaviour of the request in flight is unchanged.
type recordingResponseWriter struct {
	http.ResponseWriter
	status int
	body   []byte
	wrote  bool
}

func newRecordingWriter(w http.ResponseWriter) *recordingResponseWriter {
	return &recordingResponseWriter{ResponseWriter: w, status: http.StatusOK}
}

func (rec *recordingResponseWriter) WriteHeader(status int) {
	if rec.wrote {
		return
	}
	rec.wrote = true
	rec.status = status
	rec.ResponseWriter.WriteHeader(status)
}

func (rec *recordingResponseWriter) Write(p []byte) (int, error) {
	if !rec.wrote {
		rec.WriteHeader(http.StatusOK)
	}
	rec.body = append(rec.body, p...)
	return rec.ResponseWriter.Write(p)
}

func (rec *recordingResponseWriter) statusCode() int { return rec.status }

// responseHeaders clones the headers the handler set, so the record does not
// alias a map the server may reuse once this response is finished.
func (rec *recordingResponseWriter) responseHeaders() http.Header {
	return rec.Header().Clone()
}

func (rec *recordingResponseWriter) bodyBytes() []byte { return rec.body }

// writeRecorded replays a stored response to a retry.
func writeRecorded(w http.ResponseWriter, record idempotencyRecord) {
	status := record.status
	if status == 0 {
		status = http.StatusOK
	}
	header := w.Header()
	for name, values := range record.header {
		header[name] = values
	}
	w.WriteHeader(status)
	if _, err := w.Write(record.body); err != nil {
		// The status line is already committed, so there is no response left to
		// turn this into: the client sees a truncated replay and retries. The
		// failing write is a transport error, and only it is logged — never the
		// recorded body, which is a ciphertext response.
		slog.Error("replaying a recorded idempotent response failed", "error", err)
	}
}

// beginDelivery claims the Idempotency-Key for a delivery request and reports
// whether the caller may go on to perform the delivery.
//
// When it may not, the response has already been written: 400 for a missing
// key, 409 when an identical request is still running, or the recorded response
// when one already finished.
//
// A finished delivery is replayed rather than refused because its push to Git
// has already happened. The branch is derived from the secret's identity
// precisely so a retry lands on the same branch, and refusing the retry left
// the caller holding an error for work that had in fact succeeded. No security
// event is emitted for a replay: no delivery took place, and the original
// attempt already recorded one.
//
// The returned finish func must be deferred by the caller.
func (h *ProtectedHandlers) beginDelivery(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func(), bool) {
	key := h.idempotencyKey(r)
	if key == "" {
		writeError(w, r, http.StatusBadRequest, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key")
		return w, func() {}, false
	}
	switch decision, record := h.idempotency.begin(key); decision {
	case idempotencyReplay:
		writeRecorded(w, record)
		return w, func() {}, false
	case idempotencyInFlight:
		writeError(w, r, http.StatusConflict, "DUPLICATE_REQUEST", "Request already processed")
		return w, func() {}, false
	default:
		recorder := newRecordingWriter(w)
		return recorder, func() {
			h.idempotency.finish(key, recorder.statusCode(), recorder.responseHeaders(), recorder.bodyBytes())
		}, true
	}
}
