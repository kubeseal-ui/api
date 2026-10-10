package handlers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ssv1alpha1 "github.com/bitnami/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/go-chi/chi/v5"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

type protectedCertProvider struct{}

func (protectedCertProvider) Get(context.Context) (*x509.Certificate, error) { return nil, nil }

// errorCertProvider fails every encryption request, so a test can tell "rejected by an authorization
// check" (403) apart from "authorized, then failed downstream" (502).
type errorCertProvider struct{}

func (errorCertProvider) Get(context.Context) (*x509.Certificate, error) {
	return nil, errors.New("no certificate configured")
}

type protectedK8s struct {
	namespaces []kubernetes.Namespace
	secrets    []kubernetes.SealedSecret
	err        error
}

func (f protectedK8s) ListNamespaces(context.Context) ([]kubernetes.Namespace, error) {
	return f.namespaces, nil
}
func (f protectedK8s) GetSealedSecret(_ context.Context, namespace, name string) (kubernetes.SealedSecret, error) {
	if f.err != nil {
		return kubernetes.SealedSecret{}, f.err
	}
	for _, secret := range f.secrets {
		if secret.Name == name && secret.Namespace == namespace {
			return secret, nil
		}
	}
	return kubernetes.SealedSecret{}, kubernetes.ErrNotFound
}
func (f protectedK8s) ListSealedSecrets(context.Context, string) ([]kubernetes.SealedSecret, error) {
	return f.secrets, nil
}
func (protectedK8s) FindActiveControllerKey(context.Context) (kubernetes.ActiveKey, error) {
	return kubernetes.ActiveKey{}, nil
}
func (protectedK8s) FindAllControllerKeys(context.Context) ([]kubernetes.ActiveKey, error) {
	return nil, nil
}

func protectedIdentity(caps ...policy.Capability) authmw.Identity {
	capabilities := make([]string, 0, len(caps))
	for _, cap := range caps {
		capabilities = append(capabilities, string(cap))
	}
	return authmw.Identity{Subject: "user-1", Capabilities: capabilities}
}
func protectedRequest(method, path string, body string, id authmw.Identity) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = authmw.WithIdentity(req, id)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	ctx := chi.NewRouteContext()
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "secrets" && i+2 < len(parts) {
			ctx.URLParams.Add("namespace", parts[i+1])
			ctx.URLParams.Add("name", parts[i+2])
			break
		}
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
}

func TestNamespacesHandlerRequiresMetadataRead(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{namespaces: []kubernetes.Namespace{{Name: "apps"}}}, nil, false)
	denied := httptest.NewRecorder()
	h.NamespacesHandler(denied, protectedRequest(http.MethodGet, "/api/v1/namespaces", "", protectedIdentity()))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("denied status = %d, want 403", denied.Code)
	}
	assertErrorEnvelope(t, denied, "CAPABILITY_DENIED", "Access denied", "")
	allowed := httptest.NewRecorder()
	h.NamespacesHandler(allowed, protectedRequest(http.MethodGet, "/api/v1/namespaces", "", protectedIdentity(policy.MetadataRead)))
	if allowed.Code != http.StatusOK {
		t.Fatalf("allowed status = %d, want 200: %s", allowed.Code, allowed.Body.String())
	}
	var body struct {
		Namespaces []kubernetes.Namespace `json:"namespaces"`
	}
	if err := json.Unmarshal(allowed.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Namespaces) != 1 || body.Namespaces[0].Name != "apps" {
		t.Fatalf("unexpected body: %s", allowed.Body.String())
	}
}

func TestNamespacesHandlerIncludesServerResolvedGitMapping(t *testing.T) {
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace: "apps", Repository: "platform/config", Branch: "main",
		PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "git-auth",
		Mode: policy.GitDeliveryDirect,
	}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, nil, protectedK8s{namespaces: []kubernetes.Namespace{{Name: "apps"}, {Name: "unmanaged"}}}, nil, false)
	rr := httptest.NewRecorder()
	h.NamespacesHandler(rr, protectedRequest(http.MethodGet, "/api/v1/namespaces", "", protectedIdentity(policy.MetadataRead)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Namespaces []kubernetes.Namespace `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Namespaces) != 2 {
		t.Fatalf("namespaces = %+v", body.Namespaces)
	}
	mapped := body.Namespaces[0]
	if !mapped.GitManaged || mapped.DeliveryMode != string(policy.GitDeliveryDirect) || mapped.GitRepository != "platform/config" {
		t.Fatalf("mapped namespace = %+v", mapped)
	}
	if body.Namespaces[1].GitManaged || body.Namespaces[1].DeliveryMode != "" || body.Namespaces[1].GitRepository != "" {
		t.Fatalf("unmanaged namespace = %+v", body.Namespaces[1])
	}
}

func TestSecretsHandlerReturnsMetadataAndDriftWithoutYAML(t *testing.T) {
	live := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: db\n  namespace: ns\nspec:\n  encryptedData:\n    password: cipher\n"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/db.yaml"}, live, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "db", Namespace: "ns", Scope: "strict", KeyCount: 1, CreatedAt: "2026-09-01T12:00:00Z", YAML: live}}}, nil, false)
	rr := httptest.NewRecorder()
	h.SecretsHandler(rr, protectedRequest(http.MethodGet, "/api/v1/secrets?namespace=ns", "", protectedIdentity(policy.MetadataRead)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), live) || !strings.Contains(rr.Body.String(), `"drift":"in-sync"`) || !strings.Contains(rr.Body.String(), `"key_count":1`) {
		t.Fatalf("unexpected metadata response: %s", rr.Body.String())
	}
}

func TestSecretHandlerReturnsMetadataAndGitStatus(t *testing.T) {
	live := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: db\n  namespace: ns\nspec:\n  encryptedData:\n    password: cipher\n"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/db.yaml"}, live, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "db", Namespace: "ns", Scope: "strict", KeyCount: 1, Keys: []string{"password"}, CreatedAt: "2026-09-01T12:00:00Z", YAML: live}}}, nil, false)
	rr := httptest.NewRecorder()
	h.SecretHandler(rr, protectedRequest(http.MethodGet, "/api/v1/secrets/ns/db", "", protectedIdentity(policy.MetadataRead)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"key_count":1`) || !strings.Contains(rr.Body.String(), `"drift":"in-sync"`) || !strings.Contains(rr.Body.String(), `"sealed_secret_yaml"`) {
		t.Fatalf("unexpected detail response: %s", rr.Body.String())
	}
}

func TestProtectedErrorsUseRequestIDEnvelope(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, nil, false)
	req := protectedRequest(http.MethodGet, "/api/v1/namespaces", "", protectedIdentity())
	req.Header.Set("X-Request-Id", "req_test")
	rr := httptest.NewRecorder()
	h.NamespacesHandler(rr, req)
	assertErrorEnvelope(t, rr, "CAPABILITY_DENIED", "Access denied", "req_test")
}

func TestProtectedHandlersRejectInvalidKubernetesNames(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, false)
	for _, path := range []string{"/api/v1/secrets/Bad/name", "/api/v1/secrets/ns/Bad_Name"} {
		rr := httptest.NewRecorder()
		h.SecretHandler(rr, protectedRequest(http.MethodGet, path, "", protectedIdentity(policy.MetadataRead)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", path, rr.Code)
		}
		assertErrorEnvelope(t, rr, "INVALID_RESOURCE_NAME", "Invalid namespace or name", "")
	}
}

func TestDecryptRequiresBaseCommit(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	h.DecryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", `{"key":"password"}`, protectedIdentity(policy.SecretDecrypt)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	assertErrorEnvelope(t, rr, "INVALID_REQUEST", "Invalid request", "")
}

func mutation(key, operation, value string) map[string]string {
	return map[string]string{"key": key, "operation": operation, "value": value}
}

// batchRequest marshals a struct rather than concatenating a string, so the test need not hand-escape
// JSON and a body with several entries cannot be accidentally malformed into one that tests a
// different code path.
func batchRequest(t *testing.T, baseCommit string, mutations ...map[string]string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"mutations": mutations, "base_commit": baseCommit})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// resealResponse is a struct rather than a map because the response carries the mutation summary —
// the keys and operations that changed, without their values — alongside the manifests.
type resealResponse struct {
	YAML       string `json:"yaml"`
	Checksum   string `json:"checksum"`
	Before     string `json:"before"`
	After      string `json:"after"`
	DiffBefore string `json:"diff_before"`
	DiffAfter  string `json:"diff_after"`
	BaseCommit string `json:"base_commit"`
	// TargetPath is carried by the diff response only: it names the file the manifest was found in,
	// which is not always the path the template renders. Nothing downstream of the patch reads a path.
	TargetPath string `json:"target_path"`
	Mutations  []struct {
		Key       string `json:"key"`
		Operation string `json:"operation"`
	} `json:"mutations"`
}

func TestResealRequiresIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	h.ResealHandler(rr, protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values", batchRequest(t, "abc", mutation("password", "replace", "new")), protectedIdentity(policy.SecretSeal, policy.SecretDecrypt)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	assertErrorEnvelope(t, rr, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key", "")
}

// TestResealResponseIncludesEncryptedDiff covers the batch patch: three mutations of different kinds
// in one request produce one resealed manifest, reported without echoing the new values.
func TestResealResponseIncludesEncryptedDiff(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	live, err := w.EncryptYAML(t.Context(), `apiVersion: v1
kind: Secret
metadata:
  name: name
  namespace: ns
stringData:
  password: old
  keep: keep-old
  remove: remove-old
`, "ns", "name", crypto.StrictScope)
	if err != nil {
		t.Fatal(err)
	}
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/name.yaml"}, live, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: live}}}, w, true)
	rr := httptest.NewRecorder()
	// Replace, add, and delete together: the batch has to land as one change, which is the point of
	// the endpoint taking an array.
	body := batchRequest(t, "abc",
		mutation("password", "replace", "new-value"),
		mutation("added", "add", "added-value"),
		mutation("remove", "delete", ""),
	)
	req := protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values", body, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "patch-1")
	h.ResealHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp resealResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for field, got := range map[string]string{
		"yaml":        resp.YAML,
		"checksum":    resp.Checksum,
		"diff_before": resp.DiffBefore,
		"diff_after":  resp.DiffAfter,
	} {
		if got == "" {
			t.Fatalf("missing %q: %s", field, rr.Body.String())
		}
	}
	if resp.DiffBefore != live || resp.DiffAfter != resp.YAML || resp.DiffBefore == resp.DiffAfter {
		t.Fatalf("unexpected patch diff: %s", rr.Body.String())
	}
	// The response names the keys it changed so the UI can confirm the batch, but it must not carry
	// the values back: the caller already has them, and plaintext has no business in a response body.
	if len(resp.Mutations) != 3 {
		t.Fatalf("mutation summary = %v, want three entries", resp.Mutations)
	}
	for _, m := range resp.Mutations {
		if m.Key == "" || m.Operation == "" {
			t.Fatalf("incomplete mutation summary entry: %+v", m)
		}
	}
	if strings.Contains(rr.Body.String(), "old") || strings.Contains(rr.Body.String(), "new-value") ||
		strings.Contains(rr.Body.String(), "added-value") {
		t.Fatalf("plaintext leaked: %s", rr.Body.String())
	}
}

// TestResealRejectsAnInvalidBatch verifies that a mutation the crypto layer refuses reaches the caller
// as a 400 naming the request, not as a 502 blaming the backend. Whether a key exists is only knowable
// after decryption, so this is the path that carries that refusal out of the crypto layer.
func TestResealRejectsAnInvalidBatch(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	live, err := w.EncryptYAML(t.Context(), `apiVersion: v1
kind: Secret
metadata:
  name: name
  namespace: ns
stringData:
  password: old
`, "ns", "name", crypto.StrictScope)
	if err != nil {
		t.Fatal(err)
	}
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/name.yaml"}, live, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: live}}}, w, true)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values",
		batchRequest(t, "abc", mutation("absent", "replace", "x")),
		protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "patch-invalid")
	h.ResealHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_MUTATION", "Invalid mutation", "")
}

// TestResealInvalidBatchDoesNotSpendTheIdempotencyKey verifies the ordering inside the handler: a
// batch refused from the body alone — here an operation that is not one of the three — is refused
// before the key is claimed, so a corrected retry can reuse the key the client chose.
//
// This holds for body-only refusals, not for rule violations: whether a key exists is only knowable
// after decryption, which is after the claim. Claiming early is the deliberate trade — the claim is
// what stops a duplicate from paying for a second decrypt.
func TestResealInvalidBatchDoesNotSpendTheIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	// Refused while parsing: the operation is not one of the three.
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values",
		batchRequest(t, "abc", mutation("password", "merge", "x")),
		protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "reused")
	h.ResealHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_REQUEST", "Invalid request", "")

	// The same key on a well-formed batch must not be rejected as a duplicate.
	rr = httptest.NewRecorder()
	req = protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values",
		batchRequest(t, "abc", mutation("password", "replace", "x")),
		protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "reused")
	h.ResealHandler(rr, req)
	if rr.Code == http.StatusConflict {
		t.Fatalf("the abandoned request should not have claimed the key: %s", rr.Body.String())
	}
}

func TestDiffHandlerRejectsDuplicateIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	body := batchRequest(t, "abc", mutation("password", "replace", "new"))
	first := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", body, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	first.Header.Set("Idempotency-Key", "same")
	second := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", body, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	second.Header.Set("Idempotency-Key", "same")
	for _, req := range []*http.Request{first, second} {
		rr := httptest.NewRecorder()
		h.DiffHandler(rr, req)
		if req == second {
			if rr.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
			}
			assertErrorEnvelope(t, rr, "DUPLICATE_REQUEST", "Request already processed", "")
		}
	}
}

func TestDiffHandlerReturnsEncryptedBeforeAndAfter(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	live, err := w.EncryptYAML(t.Context(), `apiVersion: v1
kind: Secret
metadata:
  name: name
  namespace: ns
stringData:
  password: old
`, "ns", "name", crypto.StrictScope)
	if err != nil {
		t.Fatal(err)
	}
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/name.yaml"}, live, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: live}}}, w, true)
	status, statusErr := h.gitStatus(t.Context(), h.requestTransport(), "ns", "name", live, "abc", false)
	if statusErr != nil || status["drift"] != string(kubernetes.DriftSync) {
		t.Fatalf("git status=%v err=%v", status, statusErr)
	}
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", batchRequest(t, "abc", mutation("password", "replace", "new")), protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "diff-1")
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("namespace", "ns")
	ctx.URLParams.Add("name", "name")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
	h.DiffHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp resealResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Before == "" || resp.After == "" || resp.Checksum == "" || resp.BaseCommit == "" {
		t.Fatalf("incomplete diff response: %s", rr.Body.String())
	}
	if resp.Before == resp.After || resp.BaseCommit != "abc" {
		t.Fatalf("unexpected diff response: %s", rr.Body.String())
	}
	if len(resp.Mutations) != 1 || resp.Mutations[0].Key != "password" || resp.Mutations[0].Operation != "replace" {
		t.Fatalf("mutation summary does not describe the batch: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "old\n") || strings.Contains(rr.Body.String(), "new\n") {
		t.Fatalf("plaintext leaked in diff response: %s", rr.Body.String())
	}
}

// TestDiffHandlerReportsTheDiscoveredTargetPath pins the path contract of an edit: the diff names the
// file the manifest was actually found in, not the path the mapping's template renders.
//
// The client hands that name back to the delivery endpoints. Without it they fall back to the
// template, and a Secret kept in an application subdirectory — found here by the tree walk, because
// the templated path is vacant — would be written a second time at the templated path. Two files
// would then claim the same SealedSecret identity.
func TestDiffHandlerReportsTheDiscoveredTargetPath(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	live, err := w.EncryptYAML(t.Context(), `apiVersion: v1
kind: Secret
metadata:
  name: name
  namespace: ns
stringData:
  password: old
`, "ns", "name", crypto.StrictScope)
	if err != nil {
		t.Fatal(err)
	}
	// The mapping renders clusters/ns/name.yaml; the manifest lives elsewhere, so tier 1 is vacant
	// and only the tree walk finds it.
	const discovered = "custom/apps/secrets/name.yaml"
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: discovered}, live, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: live}}}, w, true)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", batchRequest(t, "abc", mutation("password", "replace", "new")), protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "diff-discovered")
	h.DiffHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp resealResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TargetPath != discovered {
		t.Fatalf("target_path = %q, want %q: %s", resp.TargetPath, discovered, rr.Body.String())
	}
}

func TestDiffHandlerRequiresIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", batchRequest(t, "abc", mutation("password", "replace", "new")), protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	h.DiffHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	assertErrorEnvelope(t, rr, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key", "")
}

func TestDecryptRejectsGitLiveDriftBeforeDecrypt(t *testing.T) {
	live := "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: name\n  namespace: ns\nspec:\n  encryptedData:\n    password: live\n"
	gitManifest := strings.Replace(live, "password: live", "password: git", 1)
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/name.yaml"}, gitManifest, "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: live}}}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	h.DecryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", `{"key":"password","base_commit":"abc"}`, protectedIdentity(policy.SecretDecrypt)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "GIT_DRIFT", "Git and live secret differ", "")
}

func TestDecryptRejectsUnavailableGitSource(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "name", Namespace: "ns", YAML: "not sealed yaml"}}}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", `{"key":"password","base_commit":"abc"}`, protectedIdentity(policy.SecretDecrypt))
	h.DecryptHandler(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "not sealed yaml") || strings.Contains(rr.Body.String(), "crypto:") {
		t.Fatalf("internal error leaked: %s", rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "GIT_DRIFT", "Git and live secret differ", "")
}

func TestEncryptRejectsOversizedBody(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, false)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", strings.Repeat("x", 10*1024*1024+1), protectedIdentity(policy.SecretSeal))
	h.EncryptHandler(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
}

// TestEncryptClusterWideRequiresAccessManage verifies that asking for a cluster-wide scope needs
// access:manage on top of secret:seal: such a SealedSecret can be unsealed in any namespace, so
// secret:seal alone must not be enough to produce one.
func TestEncryptClusterWideRequiresAccessManage(t *testing.T) {
	body := `{"namespace":"ns","name":"name","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n","scope":"cluster-wide"}`

	// errorCertProvider makes encryption fail *after* authorization, so a 403 below can only come
	// from the capability check.
	h := NewProtectedHandlers(protectedK8s{}, crypto.New(errorCertProvider{}, nil), false)

	denied := httptest.NewRecorder()
	h.EncryptHandler(denied, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal)))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 without access:manage: %s", denied.Code, denied.Body.String())
	}
	assertErrorEnvelope(t, denied, "CAPABILITY_DENIED", "Access denied", "")

	allowed := httptest.NewRecorder()
	h.EncryptHandler(allowed, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal, policy.AccessManage)))
	if allowed.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (authorized, cert provider broken): %s", allowed.Code, allowed.Body.String())
	}
}

// TestEncryptNamespaceScopedDoesNotRequireAccessManage is the control: strict and namespace-wide
// scopes stay reachable with secret:seal alone.
func TestEncryptNamespaceScopedDoesNotRequireAccessManage(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, crypto.New(errorCertProvider{}, nil), false)
	for _, scope := range []string{"strict", "namespace-wide"} {
		rr := httptest.NewRecorder()
		body := `{"namespace":"ns","name":"name","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n","scope":"` + scope + `"}`
		h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal)))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("scope %s: status = %d, want 502 (authorized): %s", scope, rr.Code, rr.Body.String())
		}
	}
}

// TestEncryptRefusesToOverwriteAnOccupiedMappedPath pins the documented "mapped target vacant" gate:
// a create whose name resolves onto a manifest that already exists would replace it silently, the
// outcome the separate create and edit flows exist to prevent.
//
// The crypto wrapper is deliberately broken, so a 409 can only come from the vacancy gate.
func TestEncryptRefusesToOverwriteAnOccupiedMappedPath(t *testing.T) {
	transport := gitops.NewLocalTransport()
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/name.yaml"}, "existing", "abc")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{}, crypto.New(errorCertProvider{}, nil), false)

	body := `{"namespace":"ns","name":"name","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n  namespace: ns\nstringData:\n  password: x\n"}`
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal)))
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "PATH_OCCUPIED", "A manifest for this Secret already exists at the mapped path", "")
}

// TestEncryptReturnsTheBranchHeadForAVacantMappedPath covers the other half of the gate: alongside
// the ciphertext the response carries the head the vacant path was checked against, so a client can
// deliver the new Secret without borrowing a base commit from some other Secret. No other endpoint
// reports a head for a namespace that has no secrets yet.
func TestEncryptReturnsTheBranchHeadForAVacantMappedPath(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	transport := gitops.NewLocalTransport()
	// A different file on the same repository and branch: this is what gives the mock transport a
	// head to report.
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "clusters/ns/other.yaml"}, "other", "head-1")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{Namespace: "ns", Repository: "platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{}, w, false)

	body := `{"namespace":"ns","name":"name","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n  namespace: ns\nstringData:\n  password: plaintext-marker\n"}`
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var response struct {
		YAML       string `json:"yaml"`
		BaseCommit string `json:"base_commit"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("invalid JSON response: %v (%s)", err, rr.Body.String())
	}
	if response.BaseCommit != "head-1" {
		t.Fatalf("base_commit = %q, want head-1", response.BaseCommit)
	}
	if response.YAML == "" || strings.Contains(response.YAML, "plaintext-marker") {
		t.Fatalf("unexpected ciphertext: %s", response.YAML)
	}
}

// TestEncryptEchoesThePathTheVacancyGateRead covers a create whose operator picked a path other than
// the mapping's default: the response names the file the gate actually checked, so the client
// delivers to that file rather than back to the rendered path, whose occupancy was never read.
//
// AllowedPaths is what lets a path other than the template be requested at all, and the echo is
// unconditional — an unmapped namespace answers with an empty string rather than a path nobody
// checked.
func TestEncryptEchoesThePathTheVacancyGateRead(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	transport := gitops.NewLocalTransport()
	// A different file on the same branch: this is what gives the mock transport a head for the
	// vacant target to be built on.
	transport.Seed(gitops.Target{Repository: "platform", Branch: "main", Path: "custom/apps/other.yaml"}, "other", "head-1")
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace: "ns", Repository: "platform", Branch: "main",
		PathTemplate: "clusters/{namespace}/{name}.yaml",
		AllowedPaths: []string{"custom/apps"},
		AuthRef:      "auth", Mode: policy.GitDeliveryDirect,
	}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, transport, protectedK8s{}, w, false)

	const chosen = "custom/apps/name.yaml"
	body, err := json.Marshal(map[string]string{
		"namespace": "ns", "name": "name", "target_path": chosen,
		"yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n  namespace: ns\nstringData:\n  password: plaintext-marker\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", string(body), protectedIdentity(policy.SecretSeal)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		YAML       string `json:"yaml"`
		BaseCommit string `json:"base_commit"`
		TargetPath string `json:"target_path"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("invalid JSON response: %v (%s)", err, rr.Body.String())
	}
	if response.TargetPath != chosen {
		t.Fatalf("target_path = %q, want %q", response.TargetPath, chosen)
	}
	if response.BaseCommit != "head-1" {
		t.Fatalf("base_commit = %q, want head-1", response.BaseCommit)
	}
}

// TestEncryptWithoutGitMappingSkipsTheVacancyGate is the control: a namespace with no mapping has no
// mapped path that could be occupied, so encrypting for it must not start demanding Git access.
func TestEncryptWithoutGitMappingSkipsTheVacancyGate(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlers(protectedK8s{}, w, false)

	body := `{"namespace":"ns","name":"name","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: name\n  namespace: ns\nstringData:\n  password: x\n"}`
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"base_commit":""`) {
		t.Fatalf("expected an empty base commit for an unmapped namespace: %s", rr.Body.String())
	}
}

func assertErrorEnvelope(t *testing.T, rr *httptest.ResponseRecorder, code, message, requestID string) {
	t.Helper()
	var body struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON error: %v (%s)", err, rr.Body.String())
	}
	if body.Error.Code != code || body.Error.Message != message || body.Error.RequestID != requestID {
		t.Fatalf("error = %+v, want %s/%s/%s", body.Error, code, message, requestID)
	}
}

func TestCanonicalSealedSecretIgnoresArgoCDTrackingAndRuntimeFields(t *testing.T) {
	gitManifest := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: example-secret
  namespace: example-ns
spec:
  encryptedData:
    key1: dummy-encrypted-val
  template:
    metadata:
      name: example-secret
      namespace: example-ns
    type: Opaque
`

	liveManifestWithArgoCD := `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: example-secret
  namespace: example-ns
  generation: 1
  resourceVersion: "12345"
  uid: "00000000-0000-0000-0000-000000000001"
  creationTimestamp: "2025-01-01T00:00:00Z"
  annotations:
    argocd.argoproj.io/tracking-id: "example-app:bitnami.com/SealedSecret:example-ns/example-secret"
    kubectl.kubernetes.io/last-applied-configuration: "{}"
  labels:
    argocd.argoproj.io/instance: "example-app"
spec:
  encryptedData:
    key1: dummy-encrypted-val
  template:
    metadata:
      creationTimestamp: null
      name: example-secret
      namespace: example-ns
    type: Opaque
status:
  observedGeneration: 1
`

	gitCanon, err := canonicalSealedSecret(gitManifest)
	if err != nil {
		t.Fatalf("git canonical failed: %v", err)
	}
	liveCanon, err := canonicalSealedSecret(liveManifestWithArgoCD)
	if err != nil {
		t.Fatalf("live canonical failed: %v", err)
	}

	if !bytes.Equal(gitCanon, liveCanon) {
		t.Fatalf("expected canonical forms to match, but they differed:\nGit:  %s\nLive: %s", string(gitCanon), string(liveCanon))
	}
}

// liveSecretManifest is what `kubectl get secret -o yaml` hands back for a live Secret: the desired
// state plus everything the API server attached to that one object, and the apply annotations that
// record how it got there.
const liveSecretManifest = `apiVersion: v1
kind: Secret
metadata:
  name: adopted
  namespace: ns
  uid: "0f8e1c2a-1111-2222-3333-444455556666"
  resourceVersion: "918273"
  generation: 4
  creationTimestamp: "2025-01-01T00:00:00Z"
  selfLink: /api/v1/namespaces/ns/secrets/adopted
  managedFields:
  - manager: kubectl
    operation: Update
  ownerReferences:
  - apiVersion: apps/v1
    kind: Deployment
    name: payments
    uid: "99999999-1111-2222-3333-444455556666"
  labels:
    app: payments-api
    argocd.argoproj.io/instance: payments
  annotations:
    owner: platform-team
    kubectl.kubernetes.io/last-applied-configuration: '{"kind":"Secret","data":{"password":"c2VjcmV0"}}'
    argocd.argoproj.io/tracking-id: payments:v1/Secret:ns/adopted
type: kubernetes.io/tls
data:
  tls.crt: Y2VydA==
  tls.key: a2V5
status:
  something: live-only
`

// TestNormalizeSecretYAMLStripsEverythingButDesiredState covers the normalizer directly, so each
// rule is pinned rather than inferred from a sealed output.
func TestNormalizeSecretYAMLStripsEverythingButDesiredState(t *testing.T) {
	normalized, err := normalizeSecretYAML(liveSecretManifest, "ns", "adopted")
	if err != nil {
		t.Fatalf("normalizeSecretYAML: %v", err)
	}

	// Kept: everything that describes what the Secret should be.
	for _, want := range []string{"kubernetes.io/tls", "app: payments-api", "owner: platform-team", "tls.crt", "tls.key"} {
		if !strings.Contains(normalized, want) {
			t.Errorf("normalized manifest dropped %q:\n%s", want, normalized)
		}
	}
	// Dropped: everything describing the live object's life rather than its content, including the
	// apply annotation that embeds the whole object.
	for _, unwanted := range []string{
		"uid:", "resourceVersion", "generation", "creationTimestamp", "selfLink", "managedFields",
		"ownerReferences", "status", "last-applied-configuration", "argocd.argoproj.io/",
		"0f8e1c2a-1111-2222-3333-444455556666",
	} {
		if strings.Contains(normalized, unwanted) {
			t.Errorf("normalized manifest kept %q:\n%s", unwanted, normalized)
		}
	}
}

// TestNormalizeSecretYAMLRefusesTheWrongDocument pins the refusals: a copy-paste flow's likeliest
// mistake is pasting the wrong manifest, and sealing one Secret's content under another's name is a
// silent failure with no error to find afterwards.
func TestNormalizeSecretYAMLRefusesTheWrongDocument(t *testing.T) {
	const secretFor = `apiVersion: v1
kind: Secret
metadata:
  name: NAME
  namespace: NS
stringData:
  password: x
`
	cases := []struct {
		name     string
		manifest string
		want     string
	}{
		{"not a Secret", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: adopted\n", "ConfigMap"},
		{"a SealedSecret", "apiVersion: bitnami.com/v1alpha1\nkind: SealedSecret\nmetadata:\n  name: adopted\n", "SealedSecret"},
		{"empty document", "---\n", "empty"},
		{"no kind at all", "metadata:\n  name: adopted\n", `kind ""`},
		{"a different name", strings.Replace(strings.Replace(secretFor, "NAME", "other", 1), "NS", "ns", 1), `names "other"`},
		{"a different namespace", strings.Replace(strings.Replace(secretFor, "NAME", "adopted", 1), "NS", "other", 1), `namespace "other"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeSecretYAML(tc.manifest, "ns", "adopted")
			if err == nil {
				t.Fatal("expected a refusal, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestEncryptSealsAnAdoptedManifest pins the end-to-end adopt path: a pasted live Secret is sealed
// through the ordinary create endpoint, and the ciphertext carries the content while dropping the
// live object's bookkeeping. No new Kubernetes permission is involved — the operator's own kubectl
// read the Secret — which is the whole reason this is a paste rather than a server-side lookup.
func TestEncryptSealsAnAdoptedManifest(t *testing.T) {
	w, _, err := crypto.NewTestCrypto()
	if err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlers(protectedK8s{}, w, false)

	body, err := json.Marshal(map[string]string{"namespace": "ns", "name": "adopted", "yaml": liveSecretManifest})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", string(body), protectedIdentity(policy.SecretSeal)))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var response struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	// The manifest is decoded, not substring-matched: the Kubernetes legacy codec emits JSON, so a
	// YAML-shaped assertion like "app: payments-api" would fail against a payload that carries the
	// label perfectly well as "app":"payments-api". Asserting on the decoded object also survives the
	// encoder changing its serialization.
	var sealed ssv1alpha1.SealedSecret
	if err := yaml.Unmarshal([]byte(response.YAML), &sealed); err != nil {
		t.Fatalf("sealed manifest is not a SealedSecret: %v\n%s", err, response.YAML)
	}
	// The type, labels, and the Secret's own annotation survive into the manifest's template.
	if sealed.Spec.Template.Type != corev1.SecretTypeTLS {
		t.Errorf("template type = %q, want %q", sealed.Spec.Template.Type, corev1.SecretTypeTLS)
	}
	if got := sealed.Spec.Template.Labels["app"]; got != "payments-api" {
		t.Errorf("template label app = %q, want %q", got, "payments-api")
	}
	if got := sealed.Spec.Template.Annotations["owner"]; got != "platform-team" {
		t.Errorf("template annotation owner = %q, want %q", got, "platform-team")
	}
	// Both values were sealed, and only as ciphertext.
	for _, key := range []string{"tls.crt", "tls.key"} {
		if sealed.Spec.EncryptedData[key] == "" {
			t.Errorf("sealed manifest has no encrypted %q:\n%s", key, response.YAML)
		}
	}
	if strings.Contains(response.YAML, "Y2VydA==") || strings.Contains(response.YAML, "a2V5") {
		t.Errorf("plaintext value survived into the sealed manifest:\n%s", response.YAML)
	}
	for _, unwanted := range []string{"last-applied-configuration", "resourceVersion", "ownerReferences", "selfLink"} {
		if strings.Contains(response.YAML, unwanted) {
			t.Errorf("sealed manifest kept %q:\n%s", unwanted, response.YAML)
		}
	}
}

// TestEncryptRefusesAManifestForAnotherSecret covers the refusal at the endpoint rather than in the
// normalizer: the operator is told which resource they pasted instead of being handed a manifest
// sealed under the wrong name.
func TestEncryptRefusesAManifestForAnotherSecret(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, false)
	body := `{"namespace":"ns","name":"adopted","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: something-else\n  namespace: ns\nstringData:\n  password: x\n"}`
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, protectedIdentity(policy.SecretSeal)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "INVALID_MANIFEST", "Manifest is not a Kubernetes Secret for this name and namespace", "")
	// The refusal names no field of the submitted manifest: the message is bounded, and the manifest
	// is not echoed back into an error body.
	if strings.Contains(rr.Body.String(), "something-else") {
		t.Fatalf("error body echoed the submitted manifest: %s", rr.Body.String())
	}
}
