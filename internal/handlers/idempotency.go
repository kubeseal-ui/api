package handlers

import (
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Nothing ever releases a claimed key, so the TTL bounds the double-submit window and the cap bounds the store; both drain oldest-first.
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
	// idempotencyReplay means an identical request already finished; its recorded response answers the retry.
	idempotencyReplay
)

// idempotencyRecord is a completed response, kept so a retry can be answered with it.
type idempotencyRecord struct {
	status int
	header http.Header
	body   []byte
}

type idempotencyEntry struct {
	expiry time.Time
	// done separates a still-running request (double submit to refuse) from a finished one (retry to answer).
	done   bool
	record idempotencyRecord
}

// idempotencyStore records which (subject, key) pairs have been claimed; order mirrors entries so both FIFO bounds drain the same prefix.
type idempotencyStore struct {
	mu      sync.Mutex
	entries map[string]*idempotencyEntry
	order   []string         // the same keys, oldest first
	now     func() time.Time // indirected so tests can move the clock
}

func newIdempotencyStore() *idempotencyStore {
	return &idempotencyStore{entries: make(map[string]*idempotencyEntry), now: time.Now}
}

// claim reports whether the caller may proceed, without recording a response; delivery endpoints use begin and finish instead.
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

// finish records the outcome of a claimed delivery; any non-2xx releases the claim, so a failure never blocks retries.
func (s *idempotencyStore) finish(key string, status int, header http.Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return // swept while the request was running
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

// evictLocked holds the store at the cap by dropping the oldest claims — the sweep cannot, since a burst inside one TTL window has nothing expired.
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

// recordingResponseWriter captures a handler's response for later replay while still writing through to the real writer.
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

// responseHeaders clones the headers, so the record does not alias a map the server may reuse.
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
		// Status line already committed; log the transport error only, never the recorded body — a ciphertext response.
		slog.Error("replaying a recorded idempotent response failed", "error", err)
	}
}

// beginDelivery claims the key for a delivery; on refusal the response is already written, and a finished delivery is replayed
// rather than refused because its push already landed. The returned finish func must be deferred by the caller.
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
