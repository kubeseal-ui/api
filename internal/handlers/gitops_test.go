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
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
)

func TestGitOpsDryRunHandlerRequiresModeCapability(t *testing.T) {
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: localProposalAdapter{}}); err != nil {
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

type failingProposalAdapter struct{}

func (failingProposalAdapter) OpenProposal(context.Context, gitops.ProposalRequest) (gitops.ProposalResult, error) {
	return gitops.ProposalResult{}, errors.New("host unavailable")
}

func TestGitOpsDeliverProposalAdapterFailureLeavesBranchAndRetryReconciles(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
	store := policy.NewPolicyStore()
	mapping := policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: failingProposalAdapter{}}
	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
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
	mapping.ProposalAdapter = localProposalAdapter{}
	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatal(err)
	}
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
	// The proposal branch names the secret's identity, not the repository or
	// the file path, so both proposal endpoints and every retry land on one
	// branch. Deriving it from the path instead produced a different branch
	// per rendered path and broke retry reconciliation.
	if result.Branch != "kubeseal-ui/payments-api" {
		t.Fatalf("branch = %q, want kubeseal-ui/payments-api", result.Branch)
	}
}

func TestGitOpsSyncStatusOptionADiscovery(t *testing.T) {
	// Seed a secret in Git located in an arbitrary subfolder (not at default pathTemplate)
	gitYAML := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: secret-value\n"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{
		Repository: "platform",
		Branch:     "main",
		Path:       "custom/apps/secrets/kubeseal-cred.yaml",
	}, gitYAML, "base-123")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace:    "cluster",
		Repository:   "platform",
		Branch:       "main",
		PathTemplate: "cluster/sealed-secrets/{namespace}/{name}.yaml",
		AuthRef:      "auth",
		Mode:         policy.GitDeliveryDirect,
	}); err != nil {
		t.Fatal(err)
	}

	liveYAML := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\n  resourceVersion: \"12345\"\n  generation: 1\nspec:\n  encryptedData:\n    key: secret-value\n"
	k8s := protectedK8s{secrets: []kubernetes.SealedSecret{
		{Name: "kubeseal-cred", Namespace: "cluster", YAML: liveYAML},
	}}

	h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)
	req := protectedRequest(http.MethodGet, "/api/v1/gitops/sync?namespace=cluster&name=kubeseal-cred", "", protectedIdentity(policy.MetadataRead))
	rr := httptest.NewRecorder()
	h.GitOpsSyncStatusHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}

	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}

	if status["file_path"] != "custom/apps/secrets/kubeseal-cred.yaml" {
		t.Fatalf("expected discovered path custom/apps/secrets/kubeseal-cred.yaml, got %v", status["file_path"])
	}
	if status["drift_status"] != "in-sync" {
		t.Fatalf("expected in-sync (ignoring volatile metadata), got %v", status["drift_status"])
	}
	if status["base_commit"] != "base-123" {
		t.Fatalf("expected base-123, got %v", status["base_commit"])
	}
}

func TestGitOpsSyncExecuteLiveToGit(t *testing.T) {
	// Secret exists in cluster and in Git at a discovered path with drift
	gitYAML := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: old-cipher\n"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{
		Repository: "platform",
		Branch:     "main",
		Path:       "custom/apps/secrets/kubeseal-cred.yaml",
	}, gitYAML, "commit-old")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace:    "cluster",
		Repository:   "platform",
		Branch:       "main",
		PathTemplate: "cluster/sealed-secrets/{namespace}/{name}.yaml",
		AuthRef:      "auth",
		Mode:         policy.GitDeliveryDirect,
	}); err != nil {
		t.Fatal(err)
	}

	liveYAML := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: new-live-cipher\n"
	k8s := protectedK8s{secrets: []kubernetes.SealedSecret{
		{Name: "kubeseal-cred", Namespace: "cluster", YAML: liveYAML},
	}}

	h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)
	body := `{"namespace":"cluster","name":"kubeseal-cred","base_commit":"commit-old"}`
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/sync", body, protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "sync-key-1")
	rr := httptest.NewRecorder()
	h.GitOpsSyncHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	// Verifies target path used the Option A discovered path
	if res["file_path"] != "custom/apps/secrets/kubeseal-cred.yaml" {
		t.Fatalf("expected sync to target discovered path, got %v", res["file_path"])
	}
	if res["argocd_sync_verified"] != false {
		t.Fatalf("expected argocd_sync_verified to be false")
	}

	// Verify content pushed to Git matches the live YAML
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{
		Repository: "platform",
		Branch:     "main",
		Path:       "custom/apps/secrets/kubeseal-cred.yaml",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != liveYAML {
		t.Fatalf("Git content mismatch: expected %q, got %q", liveYAML, string(snapshot.Content))
	}
}

