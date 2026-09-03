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

func TestSensitiveHandlerEmitsBoundedSecurityEvent(t *testing.T) {
	sink := &eventSink{}
	h := NewProtectedHandlers(protectedK8s{secret: kubernetes.SealedSecret{YAML: "not sealed yaml"}}, &crypto.Wrapper{}, true)
	h.SecurityEvents = sink
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", `{"key":"password","base_commit":"abc","value":"must-not-appear"}`, protectedIdentity(policy.SecretDecrypt))
	req.Header.Set("X-Request-Id", "req-1")
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("namespace", "ns")
	ctx.URLParams.Add("name", "name")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
	h.DecryptHandler(httptest.NewRecorder(), req)
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	e := sink.events[0]
	if e.operation != "reveal" || e.subject != "user-1" || e.namespace != "ns" || e.secret != "name" || e.requestID != "req-1" {
		t.Fatalf("unexpected event: %#v", e)
	}
	if e.key != "" || e.result != "attempt" {
		t.Fatalf("event contains unexpected sensitive data: %#v", e)
	}
}
