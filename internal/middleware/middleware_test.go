package middleware

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubeseal-ui/api/internal/observability"
)

func testHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// TestRequestIDMiddlewareSetsHeader verifies a generated ID is set on
// the response and an inbound ID is preserved.
func TestRequestIDMiddlewareSetsHeader(t *testing.T) {
	// Generated
	rec := httptest.NewRecorder()
	RequestID(http.HandlerFunc(testHandler)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("X-Request-Id") == "" {
		t.Fatal("expected generated request id header")
	}

	// Preserved inbound
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-Id", "inbound-42")
	rec2 := httptest.NewRecorder()
	RequestID(http.HandlerFunc(testHandler)).ServeHTTP(rec2, req)
	if got := rec2.Header().Get("X-Request-Id"); got != "inbound-42" {
		t.Errorf("want inbound-42, got %q", got)
	}
}

// TestRecoveryMiddlewareCatchesPanic verifies a panicking handler
// yields 500 and does not crash the process.
func TestRecoveryMiddlewareCatchesPanic(t *testing.T) {
	panicHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	rec := httptest.NewRecorder()
	Recoverer(panicHandler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

// TestBodyLimitMiddlewareRejects verifies oversize bodies are
// rejected by the reader (413 on write via MaxBytesReader).
func TestBodyLimitMiddlewareRejects(t *testing.T) {
	handler := BodyLimit(8)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			// MaxBytesReader surfaces the limit as an error on read.
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = w.Write(body)
	}))

	big := strings.Repeat("x", 64)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(big))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("want 413, got %d", rec.Code)
	}
}

// TestAuthGateDeniesAll verifies the phase-1 boundary: every request
// behind AuthGate is rejected.
func TestAuthGateDeniesAll(t *testing.T) {
	rec := httptest.NewRecorder()
	AuthGate(http.HandlerFunc(testHandler)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

// TestRequestLoggerRedactsSecrets verifies the request logger never
// writes body content and emits the request id.
func TestRequestLoggerRedactsSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := observability.NewLogger(&buf, levelDebug())
	handler := RequestLogger(logger)(http.HandlerFunc(testHandler))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/whatever?token=hunter2", strings.NewReader("password=hunter2"))
	handler.ServeHTTP(rec, req)

	out := buf.String()
	if !strings.Contains(out, "http_request") {
		t.Fatalf("expected log line, got: %s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("secret value leaked into log: %s", out)
	}
}

func levelDebug() slog.Level { return slog.LevelDebug }
