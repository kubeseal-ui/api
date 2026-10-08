package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
)

type eventSink struct {
	events []struct{ operation, subject, namespace, secret, key, mode, result, requestID string }
}

func (s *eventSink) EmitSecurityEvent(operation, subject, namespace, secret, key, mode, result, requestID string) {
	s.events = append(s.events, struct{ operation, subject, namespace, secret, key, mode, result, requestID string }{operation, subject, namespace, secret, key, mode, result, requestID})
}

func withRouteParams(r *http.Request, namespace, name string) *http.Request {
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("namespace", namespace)
	ctx.URLParams.Add("name", name)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}

func TestSensitiveHandlerEmitsBoundedSecurityEvent(t *testing.T) {
	sink := &eventSink{}
	h := NewProtectedHandlers(protectedK8s{secrets: []kubernetes.SealedSecret{{YAML: "not sealed yaml"}}}, &crypto.Wrapper{}, true)
	h.SecurityEvents = sink
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", `{"key":"password","base_commit":"abc","value":"must-not-appear"}`, protectedIdentity(policy.SecretDecrypt))
	req.Header.Set("X-Request-Id", "req-1")
	req = withRouteParams(req, "ns", "name")
	h.DecryptHandler(httptest.NewRecorder(), req)
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	e := sink.events[0]
	if e.operation != "reveal" || e.subject != "user-1" || e.namespace != "ns" || e.secret != "name" || e.requestID != "req-1" {
		t.Fatalf("unexpected event: %#v", e)
	}
	// The key *name* belongs in the event; the submitted key *value* never does.
	if e.key != "password" {
		t.Fatalf("event key = %q, want the requested key name", e.key)
	}
	if e.result != "not_found" {
		t.Fatalf("event result = %q, want not_found", e.result)
	}
}

// TestRevealRecordsOutcomeNotAttempt pins that each exit path records what
// actually happened. A constant result value (previously the literal
// "attempt") made success, failure, self-service denial, and a rotated key
// indistinguishable, so the CryptoFailures alert could never fire and the
// audit trail could not prove what a reveal did.
func TestRevealRecordsOutcomeNotAttempt(t *testing.T) {
	cases := []struct {
		name       string
		caps       []policy.Capability
		enable     bool
		secrets    []kubernetes.SealedSecret
		body       string
		wantResult string
	}{
		{
			name:       "denied without secret:decrypt",
			enable:     true,
			body:       `{"key":"k","base_commit":"abc"}`,
			wantResult: "denied",
		},
		{
			name:       "disabled when ENABLE_DECRYPT is off",
			caps:       []policy.Capability{policy.SecretDecrypt},
			enable:     false,
			body:       `{"key":"k","base_commit":"abc"}`,
			wantResult: "disabled",
		},
		{
			name:       "invalid when the key is missing",
			caps:       []policy.Capability{policy.SecretDecrypt},
			enable:     true,
			body:       `{"base_commit":"abc"}`,
			wantResult: "invalid_request",
		},
		{
			name:       "not_found when the secret does not exist",
			caps:       []policy.Capability{policy.SecretDecrypt},
			enable:     true,
			body:       `{"key":"k","base_commit":"abc"}`,
			wantResult: "not_found",
		},
		{
			name:       "conflict when Git and live differ",
			caps:       []policy.Capability{policy.SecretDecrypt},
			enable:     true,
			secrets:    []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: "not sealed yaml"}},
			body:       `{"key":"k","base_commit":"abc"}`,
			wantResult: "conflict",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &eventSink{}
			h := NewProtectedHandlers(protectedK8s{secrets: tc.secrets}, &crypto.Wrapper{}, tc.enable)
			h.SecurityEvents = sink
			req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", tc.body, protectedIdentity(tc.caps...))
			req = withRouteParams(req, "ns", "name")
			h.DecryptHandler(httptest.NewRecorder(), req)

			if len(sink.events) != 1 {
				t.Fatalf("events = %d, want exactly 1", len(sink.events))
			}
			if got := sink.events[0].result; got != tc.wantResult {
				t.Fatalf("result = %q, want %q", got, tc.wantResult)
			}
		})
	}
}

// TestDiffEmitsSecurityEvent pins that the diff endpoint is audited. It
// decrypts the complete Secret internally to produce the before/after pair,
// so it belongs in the same event stream as reveal and patch even though it
// returns ciphertext only.
func TestDiffEmitsSecurityEvent(t *testing.T) {
	sink := &eventSink{}
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	h.SecurityEvents = sink
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", `{"key":"password","operation":"replace","value":"x","base_commit":"abc"}`, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "idem-1")
	req = withRouteParams(req, "ns", "name")
	h.DiffHandler(httptest.NewRecorder(), req)

	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want exactly 1", len(sink.events))
	}
	e := sink.events[0]
	if e.operation != "diff" || e.key != "password" || e.namespace != "ns" || e.secret != "name" {
		t.Fatalf("unexpected event: %#v", e)
	}
	if e.result != "not_found" {
		t.Fatalf("result = %q, want not_found", e.result)
	}
}
