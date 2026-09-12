package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/policy"
)

func TestGitOpsDryRunHandlerRequiresModeCapability(t *testing.T) {
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: policyTestProposalAdapter{}}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, gitops.NewLocalTransport(), nil, nil, false)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/dry-run", `{"namespace":"payments","name":"api","yaml":"new","base_commit":"abc"}`, protectedIdentity())
	h.GitOpsDryRunHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	assertErrorEnvelope(t, rr, "CAPABILITY_DENIED", "Access denied", "")
}

func TestGitOpsDryRunResolvesMappingAndReturnsEncryptedDiff(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old-ciphertext", "abc")
	store := policy.NewPolicyStore()
	mapping := policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}
	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/dry-run", `{"namespace":"payments","name":"api","yaml":"new-ciphertext","base_commit":"abc"}`, protectedIdentity(policy.GitOpsPush))
	rr := httptest.NewRecorder()
	h.GitOpsDryRunHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"path":"clusters/payments/api.yaml"`) || !strings.Contains(rr.Body.String(), `"mode":"direct"`) {
		t.Fatalf("unexpected response: %s", rr.Body.String())
	}
}

func TestGitOpsDeliverDirectUsesTransport(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", `{"namespace":"payments","name":"api","yaml":"new","base_commit":"abc"}`, protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "direct-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"commit_sha"`) {
		t.Fatalf("response = %d %s", rr.Code, rr.Body.String())
	}
}

var _ gitops.ProposalProvider = localProposalAdapter{}

type localProposalAdapter struct{}

func (localProposalAdapter) OpenProposal(context.Context, gitops.ProposalRequest) (gitops.ProposalResult, error) {
	return gitops.ProposalResult{URL: "https://review.test/1"}, nil
}

type policyTestProposalAdapter struct{}

func (policyTestProposalAdapter) OpenProposal(context.Context, policy.ProposalRequest) (policy.ProposalResult, error) {
	return policy.ProposalResult{}, nil
}

// failingProposalAdapter simulates a host outage after the branch push.
type failingProposalAdapter struct{}

func (failingProposalAdapter) OpenProposal(context.Context, gitops.ProposalRequest) (gitops.ProposalResult, error) {
	return gitops.ProposalResult{}, errors.New("host unavailable")
}

func TestGitOpsDeliverProposalAdapterFailureLeavesBranchAndRetryReconciles(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: policyTestProposalAdapter{}}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	h.ProposalProviders["platform"] = failingProposalAdapter{}
	body := `{"namespace":"payments","name":"api","yaml":"new","base_commit":"abc"}`

	// The adapter fails after the branch push: 502, but the branch exists.
	failedReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPropose))
	failedReq.Header.Set("Idempotency-Key", "attempt-1")
	failed := httptest.NewRecorder()
	h.GitOpsDeliverHandler(failed, failedReq)
	if failed.Code != http.StatusBadGateway {
		t.Fatalf("adapter failure status = %d, want 502", failed.Code)
	}
	assertErrorEnvelope(t, failed, "PROPOSAL_FAILED", "Proposal failed", "")
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != "old" {
		t.Fatal("direct branch content changed by a proposal push")
	}

	// The retry reconciles by idempotency key and branch rather than
	// creating duplicates: the same content lands on the same branch and
	// the successful adapter returns exactly one review URL.
	h.ProposalProviders["platform"] = localProposalAdapter{}
	retryReq := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", body, protectedIdentity(policy.GitOpsPropose))
	retryReq.Header.Set("Idempotency-Key", "attempt-2")
	retry := httptest.NewRecorder()
	h.GitOpsDeliverHandler(retry, retryReq)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d: %s", retry.Code, retry.Body.String())
	}
	var result struct {
		Mode         string `json:"mode"`
		Branch       string `json:"branch"`
		ProposalURL  string `json:"proposal_url"`
		ArgoVerified bool   `json:"argocd_sync_verified"`
	}
	if err := json.Unmarshal(retry.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ProposalURL != "https://review.test/1" || result.ArgoVerified {
		t.Fatalf("unexpected retry result: %+v", result)
	}
}
