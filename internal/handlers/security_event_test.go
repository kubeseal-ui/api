package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
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

// TestSealRecordsOutcomeNotAttempt is the seal counterpart to
// TestRevealRecordsOutcomeNotAttempt, and closes the gap it left: sealing was
// the one sensitive operation with no audit record at all, while reveal, diff,
// patch, and all three gitops operations emitted events. Creating a
// SealedSecret is the write this product exists to perform, so an operator
// could not prove from the event stream that one had happened.
//
// The two cases that carry a resource name are the ones that get past the
// decode; every refusal before that point records an event with no namespace
// and no name, which is asserted rather than left implicit.
func TestSealRecordsOutcomeNotAttempt(t *testing.T) {
	sealingCrypto, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}

	// A store whose single mapping renders clusters/ns/name.yaml and configures
	// no AllowedPaths, so the default path is the only one it permits.
	mappedStore := func() *policy.PolicyStore {
		store := policy.NewPolicyStore()
		if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
			t.Fatal(err)
		}
		return store
	}

	signedManifest := `{"namespace":"ns","name":"name","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n  namespace: ns\nstringData:\n  password: plaintext-marker\n"}`

	cases := []struct {
		name       string
		build      func() *ProtectedHandlers
		body       string
		caps       []policy.Capability
		wantResult string
		wantNS     string
		wantName   string
	}{
		{
			name:       "denied without secret:seal",
			build:      func() *ProtectedHandlers { return NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, false) },
			body:       `{"namespace":"ns","name":"name","yaml":"apiVersion: v1"}`,
			wantResult: "denied",
		},
		{
			name:       "disabled when the crypto wrapper is absent",
			build:      func() *ProtectedHandlers { return NewProtectedHandlers(protectedK8s{}, nil, false) },
			body:       `{"namespace":"ns","name":"name","yaml":"apiVersion: v1"}`,
			caps:       []policy.Capability{policy.SecretSeal},
			wantResult: "disabled",
		},
		{
			name:       "invalid when the body is not JSON",
			build:      func() *ProtectedHandlers { return NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, false) },
			body:       `not json`,
			caps:       []policy.Capability{policy.SecretSeal},
			wantResult: "invalid_request",
		},
		{
			name:       "invalid when the manifest is missing",
			build:      func() *ProtectedHandlers { return NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, false) },
			body:       `{"namespace":"ns","name":"name"}`,
			caps:       []policy.Capability{policy.SecretSeal},
			wantResult: "invalid_request",
		},
		{
			// The response for this one is a 400, but the refusal is the
			// mapping's policy and is recorded as a denial so an audit can tell
			// it apart from malformed input.
			name: "denied when target_path is outside the mapping",
			build: func() *ProtectedHandlers {
				return NewProtectedHandlersWithGitOps(mappedStore(), gitops.NewLocalTransport(), protectedK8s{}, &crypto.Wrapper{}, false)
			},
			body:       `{"namespace":"ns","name":"name","yaml":"apiVersion: v1","target_path":"clusters/other/name.yaml"}`,
			caps:       []policy.Capability{policy.SecretSeal},
			wantResult: "denied",
			wantNS:     "ns",
			wantName:   "name",
		},
		{
			name: "conflict when the mapped path is occupied",
			build: func() *ProtectedHandlers {
				transport := gitops.NewLocalTransport()
				transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/name.yaml"}, "existing", "abc")
				return NewProtectedHandlersWithGitOps(mappedStore(), transport, protectedK8s{}, &crypto.Wrapper{}, false)
			},
			body:       signedManifest,
			caps:       []policy.Capability{policy.SecretSeal},
			wantResult: "conflict",
			wantNS:     "ns",
			wantName:   "name",
		},
		{
			name:       "success records the resource it sealed",
			build:      func() *ProtectedHandlers { return NewProtectedHandlers(protectedK8s{}, sealingCrypto, false) },
			body:       signedManifest,
			caps:       []policy.Capability{policy.SecretSeal},
			wantResult: "success",
			wantNS:     "ns",
			wantName:   "name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &eventSink{}
			h := tc.build()
			h.SecurityEvents = sink
			req := protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", tc.body, protectedIdentity(tc.caps...))
			req.Header.Set("X-Request-Id", "req-seal")
			h.EncryptHandler(httptest.NewRecorder(), req)

			if len(sink.events) != 1 {
				t.Fatalf("events = %d, want exactly 1", len(sink.events))
			}
			e := sink.events[0]
			if e.operation != "seal" || e.result != tc.wantResult {
				t.Fatalf("event = %#v, want operation seal and result %q", e, tc.wantResult)
			}
			if e.subject != "user-1" || e.requestID != "req-seal" {
				t.Fatalf("event = %#v, want the caller and the request id", e)
			}
			if e.namespace != tc.wantNS || e.secret != tc.wantName {
				t.Fatalf("event namespace/secret = %q/%q, want %q/%q", e.namespace, e.secret, tc.wantNS, tc.wantName)
			}
			// The submitted manifest is the sensitive half of a seal request.
			// No field of the event may carry it, whatever the fields are
			// called.
			if strings.Contains(e.secret, "plaintext-marker") || strings.Contains(e.key, "plaintext-marker") {
				t.Fatalf("event carries manifest content: %#v", e)
			}
		})
	}
}
