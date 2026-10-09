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

// gitChangeBody builds a GitOps request body carrying a manifest as the client
// sends it. Both endpoints verify that the payload is the SealedSecret the
// request names, so a placeholder word is not a valid request.
func gitChangeBody(t *testing.T, namespace, name, manifest, baseCommit string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"namespace": namespace, "name": name, "yaml": manifest, "base_commit": baseCommit})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// sealedManifest is a minimal SealedSecret manifest for one identity, which is
// the only shape either GitOps endpoint accepts.
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

// The dry run echoes the reviewed ciphertext back as manifest text. The client
// stores `after` and posts it straight back to /gitops/deliver, so an encoded
// echo — base64 is what encoding/json does to a []byte — would be committed to
// the repository instead of the manifest, and the file would be unreadable to
// the sealed-secrets controller.
func TestGitOpsDryRunReturnsManifestTextNotBase64(t *testing.T) {
	manifest := sealedManifest("payments", "api")
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old-ciphertext", "abc")
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
	if result.Before != "old-ciphertext" {
		t.Fatalf("before = %q, want the existing file text", result.Before)
	}
}

// An encoded payload is refused before anything is written. Accepting it is how
// a repository ends up holding a file that is valid base64 of a SealedSecret and
// nothing any consumer can read.
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
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
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
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/payments/api.yaml"}, "old", "abc")
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

// TestGitOpsSyncRefusesALiveObjectThatIsNotASealedSecret covers the sync write
// path's share of the manifest guard.
//
// Sync reads its payload from Kubernetes rather than from the request, so the
// payload is a SealedSecret for this identity by construction and the guard
// cannot fire today. It is pinned anyway because the guard is what makes
// "nothing but a manifest this mapping owns is committed" a property of the
// product rather than of two of its three write paths — and a write path that
// is exempt only because it currently cannot be reached is a hole waiting for
// the next call site.
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

	// A live object that is not a SealedSecret: the identity it is stored under
	// says nothing about the manifest inside it, which is exactly the gap the
	// guard closes.
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

// deliveryManifest is a SealedSecret for one identity with a distinguishable
// ciphertext, so a test can tell which content a repository file holds.
func deliveryManifest(namespace, name, ciphertext string) string {
	return strings.Replace(sealedManifest(namespace, name), "ciphertext", ciphertext, 1)
}

// renderedPath returns the destination the store's mapping renders for one
// identity, which is where a delivery resolves when the client names no path.
//
// A test that names a path back to the endpoints derives it here rather than
// writing out a literal: the literal is what the mapping renders for *some*
// identity, and one that has drifted from the identity under test is a path
// this mapping does not render here at all. The endpoint then refuses it — a
// 400 that is correct for the request and reads as a failure of the rule the
// test meant to pin.
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

// TestGitOpsDeliverResolvesTheDiscoveredPathWithoutBeingTold covers the write
// side of source discovery.
//
// The mapping's template is the *default* file, not necessarily the one the
// manifest lives in: when a Secret is kept in an application subdirectory the
// templated path is vacant, and a delivery that assumed the template would
// create a second file claiming an identity that already has one — leaving the
// application to read the stale ciphertext from the file nothing updated.
//
// The mapping here has no AllowedPaths on purpose: that is the configuration
// in which the mapping's own rule admits nothing but the template, so a client
// cannot name the discovered file and only the server's own discovery can put
// the change where it belongs.
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
	// ...and the template is still vacant, which is what says no second file
	// was created for this identity.
	if _, err := transport.ReadManifest(context.Background(), gitops.Target{Repository: "platform", Branch: "main", Path: templated}, ""); !errors.Is(err, gitops.ErrNotFound) {
		t.Fatalf("a second file was created at the templated path %s (err=%v)", templated, err)
	}
}

// TestGitOpsDeliverRefusesAPathThatIsNotThisSecrets is the other half of that
// rule: the client may choose among files that already belong to this
// SealedSecret, and refusing is what it gets for choosing any other.
//
// The mapping admits only its template, and the manifest is there — so a client
// naming a different file is asking to write somewhere this identity has no
// manifest, which is a bad request rather than a silent redirect to a file the
// operator never reviewed.
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

// TestGitOpsDeliverRefusesADifferentAllowedPathWhenTheFileExists is the case
// the allowlist alone would let through: the client names a path the mapping
// permits, but this identity's manifest is somewhere else.
//
// Honouring the name would write the reviewed ciphertext to a second file and
// leave the application reading the first, which is the duplicate this whole
// rule exists to prevent — and it would do it under a grant, so no policy check
// would ever flag it. The allowlist decides where a *new* manifest may go; it
// does not let a caller move one that already exists.
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

// TestGitOpsDeliverAcceptsTheMappingsTemplateWhenAnAllowlistIsSet pins the
// default destination against the allowlist.
//
// An allowlist that does not cover the template — allowed directories elsewhere
// in the repository, which is the common shape — would otherwise make the
// mapping's own default an invalid destination. That is the path
// /secrets/encrypt echoes back for a create the operator chose no path for, so
// the create would be handed a target_path the delivery endpoints then refuse,
// and the failure would land on the last step of a flow that had already
// sealed the Secret.
func TestGitOpsDeliverAcceptsTheMappingsTemplateWhenAnAllowlistIsSet(t *testing.T) {
	const namespace = "payments"
	// No file for this name anywhere on the branch, which is what makes this
	// the create flow: with no target directory chosen, the destination is the
	// mapping's own default.
	const name = "new"

	// Another file on the same branch, so the vacant destination is built on a
	// head.
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

// TestGitOpsDeliverCreatesAtANamedAllowedPathWhenTheIdentityIsNew is the
// control for the refusals above: a manifest with no file yet is exactly the
// case the allowlist is for, so the named path is honoured here.
//
// Without this the duplicate fix could pass by refusing every named path, which
// would take the create flow's target-directory selection away with it.
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

