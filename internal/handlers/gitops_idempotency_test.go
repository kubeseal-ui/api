package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/policy"
)

// A repeated Idempotency-Key on a delivery is answered with the first response
// rather than refused. The push to Git has already happened by then, and the
// branch is derived from the secret's identity so a retry is the same request
// arriving twice, not a new intent — the caller that lost the first response
// needs the commit it produced, and refusing it left them holding an error for
// work that had succeeded.
func TestGitOpsDeliverReplaysARepeatInsteadOfReExecutingIt(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	body := gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc")

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

	// Both ways this could go wrong are distinguishable in the status alone. A
	// refusal is a 409 DUPLICATE_REQUEST, and running the delivery a second time
	// is a 409 GIT_CONFLICT, because the first push moved the branch head that
	// the retry's base commit is checked against. Only a replay is a 200 whose
	// body is the one already sent.
	duplicateReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPush))
	duplicateReq.Header.Set("Idempotency-Key", "request-1")
	duplicate := httptest.NewRecorder()
	h.GitOpsDeliverHandler(duplicate, duplicateReq)
	if duplicate.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want the recorded 200: %s", duplicate.Code, duplicate.Body.String())
	}
	if duplicate.Body.String() != first.Body.String() {
		t.Fatalf("retry body = %s, want the recorded %s", duplicate.Body.String(), first.Body.String())
	}
}

// A delivery that failed released its key, so the caller can genuinely try
// again. Holding the key after a transient failure would refuse every retry
// until it expired, which is the opposite of what the key is for.
func TestGitOpsDeliverRetryAfterFailureIsNotRefused(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: failingProposalAdapter{}}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	body := gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc")

	failedReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPropose))
	failedReq.Header.Set("Idempotency-Key", "attempt-1")
	failed := httptest.NewRecorder()
	h.GitOpsDeliverHandler(failed, failedReq)
	if failed.Code != http.StatusBadGateway {
		t.Fatalf("adapter failure status = %d, want 502", failed.Code)
	}

	// The same key, not a fresh one: the failure must not have consumed it.
	mapping, ok := store.GetGitMapping("payments")
	if !ok {
		t.Fatal("mapping disappeared")
	}
	mapping.ProposalAdapter = localProposalAdapter{}
	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatal(err)
	}
	retryReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPropose))
	retryReq.Header.Set("Idempotency-Key", "attempt-1")
	retry := httptest.NewRecorder()
	h.GitOpsDeliverHandler(retry, retryReq)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after failure status = %d, want 200: %s", retry.Code, retry.Body.String())
	}
}
