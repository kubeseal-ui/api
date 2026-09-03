package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/policy"
)

func TestGitOpsDeliverRequiresAndDeduplicatesIdempotencyKey(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	body := `{"namespace":"payments","name":"api","yaml":"new","base_commit":"abc"}`

	missing := httptest.NewRecorder()
	h.GitOpsDeliverHandler(missing, protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPush)))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing key status = %d, want 400", missing.Code)
	}

	firstReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPush))
	firstReq.Header.Set("Idempotency-Key", "request-1")
	first := httptest.NewRecorder()
	h.GitOpsDeliverHandler(first, firstReq)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d: %s", first.Code, first.Body.String())
	}

	duplicateReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPush))
	duplicateReq.Header.Set("Idempotency-Key", "request-1")
	duplicate := httptest.NewRecorder()
	h.GitOpsDeliverHandler(duplicate, duplicateReq)
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409: %s", duplicate.Code, duplicate.Body.String())
	}
	assertErrorEnvelope(t, duplicate, "DUPLICATE_REQUEST", "Request already processed", "")
}
