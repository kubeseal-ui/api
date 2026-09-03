package handlers

import (
	"context"
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
