package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
)

type protectedCertProvider struct{}

func (protectedCertProvider) Get(context.Context) (*x509.Certificate, error) { return nil, nil }

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
			if i+4 < len(parts) && parts[i+3] == "values" {
				ctx.URLParams.Add("key", parts[i+4])
			}
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

func TestResealRequiresIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	h.ResealHandler(rr, protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values/password", `{"operation":"replace","base_commit":"abc"}`, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	assertErrorEnvelope(t, rr, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key", "")
}

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
	req := protectedRequest(http.MethodPatch, "/api/v1/secrets/ns/name/values/password", `{"operation":"replace","value":"new","base_commit":"abc"}`, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "patch-1")
	h.ResealHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"yaml", "checksum", "diff_before", "diff_after"} {
		if body[field] == "" {
			t.Fatalf("missing %q: %s", field, rr.Body.String())
		}
	}
	if body["diff_before"] != live || body["diff_after"] != body["yaml"] || body["diff_before"] == body["diff_after"] {
		t.Fatalf("unexpected patch diff: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "old") || strings.Contains(rr.Body.String(), "new") {
		t.Fatalf("plaintext leaked: %s", rr.Body.String())
	}
}

func TestDiffHandlerRejectsDuplicateIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	body := `{"key":"password","operation":"replace","value":"new","base_commit":"abc"}`
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
	status, statusErr := h.gitStatus(httptest.NewRequest(http.MethodPost, "/", nil), "ns", "name", live, "abc")
	if statusErr != nil || status["drift"] != kubernetes.DriftSync {
		t.Fatalf("git status=%v err=%v", status, statusErr)
	}
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", `{"key":"password","operation":"replace","value":"new","base_commit":"abc"}`, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
	req.Header.Set("Idempotency-Key", "diff-1")
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("namespace", "ns")
	ctx.URLParams.Add("name", "name")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, ctx))
	h.DiffHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"before", "after", "key", "base_commit", "checksum"} {
		if body[field] == "" {
			t.Fatalf("missing %q in response: %s", field, rr.Body.String())
		}
	}
	if body["before"] == body["after"] || body["key"] != "password" || body["base_commit"] != "abc" {
		t.Fatalf("unexpected diff response: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "old\n") || strings.Contains(rr.Body.String(), "new\n") {
		t.Fatalf("plaintext leaked in diff response: %s", rr.Body.String())
	}
}

func TestDiffHandlerRequiresIdempotencyKey(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/diff", `{"key":"password","operation":"replace","value":"new","base_commit":"abc"}`, protectedIdentity(policy.SecretSeal, policy.SecretDecrypt))
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
