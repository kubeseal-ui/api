package handlers

import (
	"context"
	"encoding/base64"
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

// gitChangeBody builds a GitOps request body carrying a manifest as the client sends it. Both
// endpoints verify that the payload is the SealedSecret the request names, so a placeholder word is
// not a valid request.
func gitChangeBody(t *testing.T, namespace, name, manifest, baseCommit string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"namespace": namespace, "name": name, "yaml": manifest, "base_commit": baseCommit})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// sealedManifest is a minimal SealedSecret manifest for one identity, the only shape either GitOps
// endpoint accepts.
func sealedManifest(namespace, name string) string {
	return "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: " + name +
		"\n  namespace: " + namespace + "\nspec:\n  encryptedData:\n    key: ciphertext\n"
}

func TestGitOpsDryRunHandlerRequiresModeCapability(t *testing.T) {
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: localProposalAdapter{}}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, gitops.NewLocalTransport(), nil, nil, false)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/dry-run", gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc"), protectedIdentity())
	h.GitOpsDryRunHandler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	assertErrorEnvelope(t, rr, "CAPABILITY_DENIED", "Access denied: missing capability gitops:propose", "")
}

func TestGitOpsDryRunResolvesMappingAndReturnsEncryptedDiff(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, deliveryManifest("payments", "api", "old-ciphertext"), "abc")
	store := policy.NewPolicyStore()
	mapping := policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}
	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/dry-run", gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc"), protectedIdentity(policy.GitOpsPush))
	rr := httptest.NewRecorder()
	h.GitOpsDryRunHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"path":"clusters/payments/api.yaml"`) || !strings.Contains(rr.Body.String(), `"mode":"direct"`) {
		t.Fatalf("unexpected response: %s", rr.Body.String())
	}
}

// The dry run echoes the reviewed ciphertext back as manifest text. The client stores `after` and
// posts it straight back to /gitops/deliver, so an encoded echo — base64 is what encoding/json does
// to a []byte — would be committed to the repository instead of the manifest, and the file would be
// unreadable to the sealed-secrets controller.
func TestGitOpsDryRunReturnsManifestTextNotBase64(t *testing.T) {
	manifest := sealedManifest("payments", "api")
	existing := deliveryManifest("payments", "api", "old-ciphertext")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, existing, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	rr := httptest.NewRecorder()
	h.GitOpsDryRunHandler(rr, protectedRequest(http.MethodPost, "/api/v1/gitops/dry-run", gitChangeBody(t, "payments", "api", manifest, "abc"), protectedIdentity(policy.GitOpsPush)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}

	var result struct {
		Before string `json:"before"`
		After  string `json:"after"`
		Diff   string `json:"diff"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.After != manifest || result.Diff != manifest {
		t.Fatalf("after = %q, want the manifest text %q", result.After, manifest)
	}
	if result.Before != existing {
		t.Fatalf("before = %q, want the existing file text", result.Before)
	}
}

// An encoded payload is refused before anything is written: accepting it is how a repository ends up
// holding a file that is valid base64 of a SealedSecret and nothing any consumer can read.
func TestGitOpsDeliveryRejectsAnEncodedManifest(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old-ciphertext", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	encoded := base64.StdEncoding.EncodeToString([]byte(sealedManifest("payments", "api")))
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", gitChangeBody(t, "payments", "api", encoded, "abc"), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "encoded-1")
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_MANIFEST", "Manifest is not a SealedSecret for this name and namespace", "")

	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != "old-ciphertext" {
		t.Fatalf("repository content changed by a refused delivery: %q", string(snapshot.Content))
	}
}

func TestGitOpsDeliverDirectUsesTransport(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, deliveryManifest("payments", "api", "old"), "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc"), protectedIdentity(policy.GitOpsPush))
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
	existing := deliveryManifest("payments", "api", "old")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, existing, "abc")
	store := policy.NewPolicyStore()
	mapping := policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryProposal, ProposalAdapter: failingProposalAdapter{}}
	if err := store.SetGitMapping(mapping); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)
	body := gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc")

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
	if string(snapshot.Content) != existing {
		t.Fatal("direct branch content changed by a proposal push")
	}

	// The retry reconciles by idempotency key and branch rather than creating duplicates: the same
	// content lands on the same branch and the successful adapter returns exactly one review URL.
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
	// The proposal branch names the secret's identity, not the repository or the file path, so both
	// proposal endpoints and every retry land on one branch. Deriving it from the path instead
	// produced a different branch per rendered path and broke retry reconciliation.
	if result.Branch != "kubeseal-ui/payments-api" {
		t.Fatalf("branch = %q, want kubeseal-ui/payments-api", result.Branch)
	}
}

func TestGitOpsSyncStatusOptionADiscovery(t *testing.T) {
	// A secret in Git in an arbitrary subfolder, not at the default pathTemplate.
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

// Drift says the live Secret and the file differ, never which of them moved. These two cases pin
// the distinction the sync control turns on: a live Secret matching the version the file held
// before its last change means Git moved, so a sync would discard the change that moved it; a live
// Secret matching nothing in that history was edited in the cluster, which a sync is the fix for.
func TestGitOpsSyncStatusTellsWhichSideMoved(t *testing.T) {
	const path = "cluster/sealed-secrets/cluster/kubeseal-cred.yaml"
	previous := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: previous\n"
	current := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: current\n"
	handEdit := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: hand-edit\n"

	statusFor := func(live string) map[string]any {
		t.Helper()
		transport := gitops.NewLocalTransport()
		transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: path}, previous, "commit-1")
		transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: path}, current, "commit-2")

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
		k8s := protectedK8s{secrets: []kubernetes.SealedSecret{
			{Name: "kubeseal-cred", Namespace: "cluster", YAML: live},
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
		return status
	}

	if moved := statusFor(previous); moved["drift_status"] != "diverged" || moved["git_moved_ahead"] != true {
		t.Fatalf("live still at the superseded version: %v", moved)
	}
	// Report-only: the server still accepts the sync, so a client that ignores the flag is not
	// left without a way to ask for it.
	if edited := statusFor(handEdit); edited["drift_status"] != "diverged" || edited["git_moved_ahead"] != false || edited["can_sync"] != true {
		t.Fatalf("hand-edited live Secret: %v", edited)
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

	// The sync targeted the discovered path, not the rendered template.
	if res["file_path"] != "custom/apps/secrets/kubeseal-cred.yaml" {
		t.Fatalf("expected sync to target discovered path, got %v", res["file_path"])
	}
	if res["argocd_sync_verified"] != false {
		t.Fatalf("expected argocd_sync_verified to be false")
	}

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

// TestGitOpsSyncRefusesALiveObjectThatIsNotASealedSecret covers the sync write path's share of the
// manifest guard. Sync reads its payload from Kubernetes rather than the request, so the payload is a
// SealedSecret for this identity by construction and the guard cannot fire today; it is pinned anyway
// because the guard is what makes "nothing but a manifest this mapping owns is committed" a property
// of the product rather than of two of its three write paths.
func TestGitOpsSyncRefusesALiveObjectThatIsNotASealedSecret(t *testing.T) {
	const existing = "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: old-cipher\n"
	const path = "custom/apps/secrets/kubeseal-cred.yaml"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: path}, existing, "commit-old")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace: "cluster", Repository: "platform", Branch: "main",
		PathTemplate: "cluster/sealed-secrets/{namespace}/{name}.yaml",
		AuthRef:      "auth", Mode: policy.GitDeliveryDirect,
	}); err != nil {
		t.Fatal(err)
	}

	// A live object that is not a SealedSecret: the identity it is stored under says nothing about
	// the manifest inside it, which is exactly the gap the guard closes.
	k8s := protectedK8s{secrets: []kubernetes.SealedSecret{
		{Name: "kubeseal-cred", Namespace: "cluster", YAML: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nstringData:\n  password: plaintext\n"},
	}}

	h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)
	body := `{"namespace":"cluster","name":"kubeseal-cred","base_commit":"commit-old"}`
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/sync", body, protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "sync-refused-1")
	rr := httptest.NewRecorder()
	h.GitOpsSyncHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_MANIFEST", "Live object is not a SealedSecret for this name and namespace", "")

	// The refusal is only worth anything if the repository is untouched.
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: path}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != existing {
		t.Fatalf("Git content changed despite the refusal: %q", string(snapshot.Content))
	}
}

// deliveryManifest is a SealedSecret for one identity with a distinguishable ciphertext, so a test
// can tell which content a repository file holds.
func deliveryManifest(namespace, name, ciphertext string) string {
	return strings.Replace(sealedManifest(namespace, name), "ciphertext", ciphertext, 1)
}

// renderedPath returns the destination the store's mapping renders for one identity, which is where a
// delivery resolves when the client names no path.
//
// A test that names a path back to the endpoints derives it here rather than writing a literal: a
// literal that has drifted from the identity under test is a path this mapping does not render, and
// the endpoint then refuses it with a 400 that reads as a failure of the rule the test meant to pin.
func renderedPath(t *testing.T, store *policy.PolicyStore, namespace, name string) string {
	t.Helper()
	mapping, ok := store.GetGitMapping(namespace)
	if !ok {
		t.Fatalf("no Git mapping for namespace %s", namespace)
	}
	path := mapping.RenderPath(namespace, name)
	if path == "" {
		t.Fatalf("the mapping for %s renders no path for %s/%s", namespace, namespace, name)
	}
	return path
}

// TestGitOpsDeliverResolvesTheDiscoveredPathWithoutBeingTold covers the write side of source
// discovery. The mapping's template is the *default* file, not necessarily the one the manifest lives
// in: when a Secret is kept in an application subdirectory the templated path is vacant, and a
// delivery that assumed the template would create a second file claiming an identity that already has
// one — leaving the application to read the stale ciphertext from the file nothing updated.
//
// The mapping has no AllowedPaths on purpose: its own rule then admits nothing but the template, so a
// client cannot name the discovered file and only the server's own discovery can put the change where
// it belongs.
func TestGitOpsDeliverResolvesTheDiscoveredPathWithoutBeingTold(t *testing.T) {
	const discovered = "custom/apps/secrets/api.yaml"
	const templated = "clusters/payments/api.yaml"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: discovered}, deliveryManifest("payments", "api", "old-cipher"), "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	updated := deliveryManifest("payments", "api", "new-cipher")
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", gitChangeBody(t, "payments", "api", updated, "abc"), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-discovered-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["file_path"] != discovered {
		t.Fatalf("file_path = %v, want %s", res["file_path"], discovered)
	}

	// The file that was found is the file that was written...
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: discovered}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != updated {
		t.Fatalf("reviewed file not updated: %q", string(snapshot.Content))
	}
	// ...and the template is still vacant, which is what says no second file was created.
	if _, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, ""); !errors.Is(err, gitops.ErrNotFound) {
		t.Fatalf("a second file was created at the templated path %s (err=%v)", templated, err)
	}
}

// TestGitOpsDeliverRefusesAPathThatIsNotThisSecrets is the other half of that rule: the client may
// choose among files that already belong to this SealedSecret, and refusing is what it gets for
// choosing any other.
//
// The mapping admits only its template and the manifest is there, so a client naming a different file
// is asking to write somewhere this identity has no manifest — a bad request rather than a silent
// redirect to a file the operator never reviewed.
func TestGitOpsDeliverRefusesAPathThatIsNotThisSecrets(t *testing.T) {
	const templated = "clusters/payments/api.yaml"
	const elsewhere = "clusters/payments/other.yaml"
	existing := deliveryManifest("payments", "api", "old-cipher")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: templated}, existing, "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	body, err := json.Marshal(map[string]string{
		"namespace": "payments", "name": "api", "base_commit": "abc",
		"yaml": deliveryManifest("payments", "api", "new-cipher"), "target_path": elsewhere,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-refused-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping", "")

	// Nothing was written anywhere: not the path that was asked for, and not
	// the template it was refused in favour of.
	if _, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: elsewhere}, ""); !errors.Is(err, gitops.ErrNotFound) {
		t.Fatalf("refused delivery wrote %s (err=%v)", elsewhere, err)
	}
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != existing {
		t.Fatalf("refused delivery wrote the template: %q", string(snapshot.Content))
	}
}

// TestGitOpsDeliverRefusesADifferentAllowedPathWhenTheFileExists is the case the allowlist alone
// would let through: the client names a path the mapping permits, but this identity's manifest is
// somewhere else.
//
// Honouring the name would write the reviewed ciphertext to a second file and leave the application
// reading the first — the duplicate this rule exists to prevent — and it would do it under a grant,
// so no policy check would flag it. The allowlist decides where a *new* manifest may go; it does not
// let a caller move one that already exists.
func TestGitOpsDeliverRefusesADifferentAllowedPathWhenTheFileExists(t *testing.T) {
	const templated = "clusters/payments/api.yaml"
	const allowed = "custom/apps/api.yaml"
	existing := deliveryManifest("payments", "api", "old-cipher")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: templated}, existing, "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AllowedPaths: []string{"custom/apps"}, AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	body, err := json.Marshal(map[string]string{
		"namespace": "payments", "name": "api", "base_commit": "abc",
		"yaml": deliveryManifest("payments", "api", "new-cipher"), "target_path": allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-allowed-elsewhere-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping", "")

	if _, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: allowed}, ""); !errors.Is(err, gitops.ErrNotFound) {
		t.Fatalf("refused delivery wrote the allowed path %s (err=%v)", allowed, err)
	}
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != existing {
		t.Fatalf("refused delivery wrote the file it lives in: %q", string(snapshot.Content))
	}
}

// TestGitOpsDeliverAcceptsTheMappingsTemplateWhenAnAllowlistIsSet pins the default destination against
// the allowlist. An allowlist that does not cover the template — allowed directories elsewhere in the
// repository, the common shape — would otherwise make the mapping's own default an invalid
// destination. That is exactly the path /secrets/encrypt echoes back for a create the operator chose no
// path for, so the create would be handed a target_path the delivery endpoints then refuse, and the
// failure would land on the last step of a flow that had already sealed the Secret.
func TestGitOpsDeliverAcceptsTheMappingsTemplateWhenAnAllowlistIsSet(t *testing.T) {
	const namespace = "payments"
	// No file for this name anywhere on the branch: this is the create flow, and with no target
	// directory chosen the destination is the mapping's own default.
	const name = "new"

	// Another file on the same branch, so the vacant destination is built on a head.
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "custom/apps/other.yaml"}, "other", "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: namespace, Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AllowedPaths: []string{"custom/apps"}, AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	templated := renderedPath(t, store, namespace, name)
	created := deliveryManifest(namespace, name, "fresh-cipher")
	body, err := json.Marshal(map[string]string{
		"namespace": namespace, "name": name, "base_commit": "abc",
		"yaml": created, "target_path": templated,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-template-with-allowlist-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["file_path"] != templated {
		t.Fatalf("file_path = %v, want the mapping's template %s", res["file_path"], templated)
	}
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != created {
		t.Fatalf("template holds %q, want the created manifest", string(snapshot.Content))
	}
}

// TestGitOpsDeliverCreatesAtANamedAllowedPathWhenTheIdentityIsNew is the control for the refusals
// above: a manifest with no file yet is exactly the case the allowlist is for, so the named path is
// honoured here. Without this the duplicate fix could pass by refusing every named path, taking the
// create flow's target-directory selection away with it.
func TestGitOpsDeliverCreatesAtANamedAllowedPathWhenTheIdentityIsNew(t *testing.T) {
	const namespace = "payments"
	const name = "new"
	const chosen = "custom/apps/new.yaml"
	// Another file on the same branch, so the vacant target is built on a head.
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "custom/apps/other.yaml"}, "other", "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: namespace, Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AllowedPaths: []string{"custom/apps"}, AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	templated := renderedPath(t, store, namespace, name)
	created := deliveryManifest(namespace, name, "fresh-cipher")
	body, err := json.Marshal(map[string]string{
		"namespace": namespace, "name": name, "base_commit": "abc",
		"yaml": created, "target_path": chosen,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-new-allowed-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["file_path"] != chosen {
		t.Fatalf("file_path = %v, want %s", res["file_path"], chosen)
	}
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: chosen}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != created {
		t.Fatalf("chosen path holds %q, want the created manifest", string(snapshot.Content))
	}
	if _, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, ""); !errors.Is(err, gitops.ErrNotFound) {
		t.Fatalf("the create also wrote the template %s (err=%v)", templated, err)
	}
}

// TestGitOpsSyncStatusReportsTheHeadForALiveOnlySecret covers the drift the sync control exists for: a
// Secret that is live in the cluster and has no manifest in Git at all.
//
// The head is what the client has to send back with the sync, and the sync endpoint refuses an empty
// base commit. A git state that reports this drift without one tells the client it can sync while
// handing it nothing to sync with, so the status is read here for the head and the sync is then
// performed with what the status reported rather than with a value the test already knew.
func TestGitOpsSyncStatusReportsTheHeadForALiveOnlySecret(t *testing.T) {
	const head = "head-live-only"
	// Git holds a different SealedSecret, so the branch has a head and the tree walk has something to
	// search — this identity is genuinely absent rather than absent because Git could not be read.
	transport := gitops.NewLocalTransport()
	transport.Seed(
		gitops.Target{Repository: "platform", Branch: "main", Path: "custom/apps/secrets/other.yaml"},
		"apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: other\n  namespace: cluster\nspec:\n  encryptedData:\n    key: other-cipher\n",
		head,
	)

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

	liveYAML := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: kubeseal-cred\n  namespace: cluster\nspec:\n  encryptedData:\n    key: live-cipher\n"
	k8s := protectedK8s{secrets: []kubernetes.SealedSecret{
		{Name: "kubeseal-cred", Namespace: "cluster", YAML: liveYAML},
	}}

	h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)
	rr := httptest.NewRecorder()
	h.GitOpsSyncStatusHandler(rr, protectedRequest(http.MethodGet, "/api/v1/gitops/sync?namespace=cluster&name=kubeseal-cred", "", protectedIdentity(policy.MetadataRead)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}

	var status map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["drift_status"] != "live_only" {
		t.Fatalf("drift_status = %v, want live_only", status["drift_status"])
	}
	// The two fields have to agree: can_sync is only an offer the client can take up with a head.
	if status["can_sync"] != true {
		t.Fatalf("can_sync = %v, want true", status["can_sync"])
	}
	base, _ := status["base_commit"].(string)
	if base != head {
		t.Fatalf("base_commit = %v, want %q", status["base_commit"], head)
	}

	body, err := json.Marshal(map[string]string{"namespace": "cluster", "name": "kubeseal-cred", "base_commit": base})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/sync", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "sync-live-only-1")
	rr = httptest.NewRecorder()
	h.GitOpsSyncHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	// The live Secret is in Git now, at the mapping's rendered path: there was no file for this
	// identity to be discovered at.
	const path = "cluster/sealed-secrets/cluster/kubeseal-cred.yaml"
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: path}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != liveYAML {
		t.Fatalf("Git content mismatch: expected %q, got %q", liveYAML, string(snapshot.Content))
	}
}

// TestGitOpsDeliverRefusesATargetPathThatCleansOutsideTheAllowlist pins the allowlist against the
// path string it used to never clean.
//
// `custom/apps/../clusters/payments.yaml` passes a prefix test on `custom/apps` while the real
// transport joins the raw string onto the worktree, where the filesystem cleans it and the commit
// writes `clusters/payments.yaml` — a file outside the grant, over whatever was there.
func TestGitOpsDeliverRefusesATargetPathThatCleansOutsideTheAllowlist(t *testing.T) {
	const escape = "custom/apps/../clusters/payments.yaml"
	const victim = "clusters/payments.yaml"
	victimContent := deliveryManifest("payments", "other", "other-cipher")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: victim}, victimContent, "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AllowedPaths: []string{"custom/apps"}, AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	body, err := json.Marshal(map[string]string{
		"namespace": "payments", "name": "api", "base_commit": "abc",
		"yaml": deliveryManifest("payments", "api", "new-cipher"), "target_path": escape,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-escape-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping", "")

	// The in-memory transport keys entries by the string it was handed, so it cannot itself show the
	// write landing in the cleaned file; the refusal above is what pins this. The content check
	// covers the other direction: nothing was written under either spelling.
	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: victim}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Content) != victimContent {
		t.Fatalf("refused delivery wrote %s: %q", victim, string(snapshot.Content))
	}
}

// TestGitOpsDeliverRefusesATemplatedPathHeldByAnotherSecret covers the create whose default
// destination is already taken.
//
// Discovery reads the templated path first and reports what it finds there. A file that is not this
// identity's manifest used to be reported as "no manifest for this identity", which the create then
// read as a vacancy and wrote into — replacing the other Secret's sealed data with this one's, while
// the audit trail recorded a successful delivery.
func TestGitOpsDeliverRefusesATemplatedPathHeldByAnotherSecret(t *testing.T) {
	const templated = "clusters/payments/api.yaml"
	occupied := deliveryManifest("payments", "somebody-else", "other-cipher")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: templated}, occupied, "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", gitChangeBody(t, "payments", "api", deliveryManifest("payments", "api", "new-cipher"), "abc"), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-occupied-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "PATH_OCCUPIED", "Another manifest is already committed at this path", "")

	held, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(held.Content) != occupied {
		t.Fatalf("refused delivery replaced the occupant: %q", string(held.Content))
	}
}

// TestGitOpsDeliverRefusesANamedAllowedPathThatIsOccupied is the allowlist half of that rule: the
// allowlist grants a destination, not the right to replace what is already at it. A named path
// holding another identity's manifest is refused even though the mapping admits the path.
func TestGitOpsDeliverRefusesANamedAllowedPathThatIsOccupied(t *testing.T) {
	const chosen = "custom/apps/taken.yaml"
	occupied := deliveryManifest("payments", "somebody-else", "other-cipher")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: chosen}, occupied, "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AllowedPaths: []string{"custom/apps"}, AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	body, err := json.Marshal(map[string]string{
		"namespace": "payments", "name": "api", "base_commit": "abc",
		"yaml": deliveryManifest("payments", "api", "new-cipher"), "target_path": chosen,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "deliver-occupied-named-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "PATH_OCCUPIED", "Another manifest is already committed at this path", "")

	held, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: chosen}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(held.Content) != occupied {
		t.Fatalf("refused delivery replaced the occupant: %q", string(held.Content))
	}
}

// TestGitOpsSyncRefusesAMappedFileHoldingAnotherSecret is the state the drift report calls
// `drift_reason: identity` — the one divergence a sync cannot resolve, because the file the mapping
// points at belongs to something else.
//
// The refusal has to belong to the endpoint: a sync that committed this Secret's ciphertext over the
// other one's would take the other application's Secret out of Git and record a successful sync of
// this one. The status report must not offer the action either, so both halves are asserted here —
// an offer the endpoint refuses is a button that only ever returns a conflict.
func TestGitOpsSyncRefusesAMappedFileHoldingAnotherSecret(t *testing.T) {
	const templated = "clusters/payments/api.yaml"
	occupied := deliveryManifest("payments", "somebody-else", "other-cipher")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: templated}, occupied, "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	live := deliveryManifest("payments", "api", "live-cipher")
	k8s := protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "api", Namespace: "payments", YAML: live}}}
	h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)

	statusReq := protectedRequest(http.MethodGet, "/api/v1/gitops/sync/status?namespace=payments&name=api", "", protectedIdentity(policy.MetadataRead))
	statusRR := httptest.NewRecorder()
	h.GitOpsSyncStatusHandler(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", statusRR.Code, statusRR.Body.String())
	}
	var status map[string]any
	if err := json.Unmarshal(statusRR.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["drift_status"] != "diverged" || status["can_sync"] != false {
		t.Fatalf("drift_status = %v, can_sync = %v; want diverged and false", status["drift_status"], status["can_sync"])
	}

	body, err := json.Marshal(map[string]string{"namespace": "payments", "name": "api", "base_commit": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/sync", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "sync-occupied-1")
	rr := httptest.NewRecorder()
	h.GitOpsSyncHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "PATH_OCCUPIED", "Another manifest is already committed at this path", "")

	held, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(held.Content) != occupied {
		t.Fatalf("refused sync replaced the occupant: %q", string(held.Content))
	}
}

// multiDocFile builds a two-SealedSecret file holding `sibling` and the secret under test, so a
// delivery or sync that assumed one document per file would visibly drop the sibling.
func multiDocFile(namespace, name, ciphertext, sibling string) string {
	return sealedManifest(namespace, name) + "---\n" + sibling
}

// TestGitOpsDeliverSplicesIntoAMultiDocumentFile pins the fix for the last open audit finding: the
// templated path holds several SealedSecret documents, and delivering to one of them must replace
// only its own document, leaving the sibling byte for byte intact.
func TestGitOpsDeliverSplicesIntoAMultiDocumentFile(t *testing.T) {
	sibling := sealedManifest("payments", "sidecar")
	path := "clusters/payments/api.yaml"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: path}, multiDocFile("payments", "api", "old", sibling), "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	req := protectedRequest(http.MethodPost, "/api/v1/gitops/deliver", gitChangeBody(t, "payments", "api", deliveryManifest("payments", "api", "new"), "abc"), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "multidoc-deliver-1")
	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("deliver = %d %s", rr.Code, rr.Body.String())
	}

	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: path}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapshot.Content), "key: new") {
		t.Fatalf("delivered ciphertext absent: %q", string(snapshot.Content))
	}
	if !strings.HasSuffix(string(snapshot.Content), sibling) {
		t.Fatalf("sibling document did not survive byte for byte: %q", string(snapshot.Content))
	}
}

// TestGitOpsDryRunReturnsTheMergedMultiDocumentFile covers the client contract that rests on the
// splice: `after` is the whole merged file, so the reviewed artifact and the delivery re-splice see
// the same document set rather than a file that would overwrite the siblings.
func TestGitOpsDryRunReturnsTheMergedMultiDocumentFile(t *testing.T) {
	sibling := sealedManifest("payments", "sidecar")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, multiDocFile("payments", "api", "old", sibling), "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, nil, nil, false)

	req := protectedRequest(http.MethodPost, "/api/v1/gitops/dry-run", gitChangeBody(t, "payments", "api", deliveryManifest("payments", "api", "new"), "abc"), protectedIdentity(policy.GitOpsPush))
	rr := httptest.NewRecorder()
	h.GitOpsDryRunHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry-run = %d %s", rr.Code, rr.Body.String())
	}
	var diff struct {
		After string `json:"after"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &diff); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diff.After, "key: new") || !strings.Contains(diff.After, "name: sidecar") {
		t.Fatalf("after is not the merged file: %q", diff.After)
	}
}

// TestGitOpsSyncSplicesIntoAMultiDocumentFile covers the live-to-Git direction of the same contract.
func TestGitOpsSyncSplicesIntoAMultiDocumentFile(t *testing.T) {
	sibling := sealedManifest("payments", "sidecar")
	path := "clusters/payments/api.yaml"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: path}, multiDocFile("payments", "api", "old", sibling), "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	live := deliveryManifest("payments", "api", "live-cipher")
	k8s := protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "api", Namespace: "payments", YAML: live}}}
	h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)

	body, err := json.Marshal(map[string]string{"namespace": "payments", "name": "api", "base_commit": "abc"})
	if err != nil {
		t.Fatal(err)
	}
	req := protectedRequest(http.MethodPost, "/api/v1/gitops/sync", string(body), protectedIdentity(policy.GitOpsPush))
	req.Header.Set("Idempotency-Key", "multidoc-sync-1")
	rr := httptest.NewRecorder()
	h.GitOpsSyncHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync = %d %s", rr.Code, rr.Body.String())
	}

	snapshot, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: path}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snapshot.Content), "key: live-cipher") {
		t.Fatalf("live ciphertext absent: %q", string(snapshot.Content))
	}
	if !strings.HasSuffix(string(snapshot.Content), sibling) {
		t.Fatalf("sibling document did not survive byte for byte: %q", string(snapshot.Content))
	}
}

// TestSyncStatusComparesTheMatchedDocument pins the read side of the same contract: drift status of
// a Secret in a multi-document file is decided against that Secret's document, not the file's first
// one, or the second Secret reports identity drift against its sibling's manifest.
func TestSyncStatusComparesTheMatchedDocument(t *testing.T) {
	path := "clusters/payments/api.yaml"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: path}, multiDocFile("payments", "api", "current", sealedManifest("payments", "sidecar")), "abc")

	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "payments", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}

	statusFor := func(t *testing.T, name, live string) map[string]any {
		t.Helper()
		k8s := protectedK8s{secrets: []kubernetes.SealedSecret{{Name: name, Namespace: "payments", YAML: live}}}
		h := NewProtectedHandlersWithGitOps(store, transport, k8s, nil, false)
		req := protectedRequest(http.MethodGet, "/api/v1/gitops/sync?namespace=payments&name="+name, "", protectedIdentity(policy.MetadataRead))
		rr := httptest.NewRecorder()
		h.GitOpsSyncStatusHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status = %d %s", name, rr.Code, rr.Body.String())
		}
		var status map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		return status
	}

	// The second document's Secret compares against its own document: matching it is in sync
	// (sealedManifest's literal ciphertext), and a stale ciphertext is ciphertext drift, never identity.
	if got := statusFor(t, "sidecar", sealedManifest("payments", "sidecar")); got["drift_status"] != "in-sync" {
		t.Fatalf("second document in sync: %v", got)
	}
	stale := statusFor(t, "sidecar", deliveryManifest("payments", "sidecar", "stale"))
	// The endpoint does not expose drift_reason; can_sync is the observable that the reason is not identity.
	if stale["drift_status"] != "diverged" || stale["can_sync"] != true {
		t.Fatalf("second document stale = %v", stale)
	}
}
