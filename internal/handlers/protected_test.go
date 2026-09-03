package handlers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
)

type protectedCertProvider struct{}

func (protectedCertProvider) Get(context.Context) (*x509.Certificate, error) { return nil, nil }

type protectedK8s struct {
	namespaces []kubernetes.Namespace
	secret     kubernetes.SealedSecret
	err        error
}

func (f protectedK8s) ListNamespaces(context.Context) ([]kubernetes.Namespace, error) {
	return f.namespaces, nil
}
func (f protectedK8s) GetSealedSecret(context.Context, string, string) (kubernetes.SealedSecret, error) {
	if f.err != nil {
		return kubernetes.SealedSecret{}, f.err
	}
	if f.secret.YAML != "" {
		return f.secret, nil
	}
	return kubernetes.SealedSecret{}, kubernetes.ErrNotFound
}
func (protectedK8s) ListSealedSecrets(context.Context, string) ([]kubernetes.SealedSecret, error) {
	return nil, nil
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
	return authmw.WithIdentity(req, id)
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

func TestDecryptDoesNotExposeCryptoError(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{secret: kubernetes.SealedSecret{YAML: "not sealed yaml"}}, &crypto.Wrapper{}, true)
	rr := httptest.NewRecorder()
	req := protectedRequest(http.MethodPost, "/api/v1/secrets/ns/name/reveal", `{"key":"password","base_commit":"abc"}`, protectedIdentity(policy.SecretDecrypt))
	h.DecryptHandler(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "not sealed yaml") || strings.Contains(rr.Body.String(), "crypto:") {
		t.Fatalf("internal error leaked: %s", rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "DECRYPTION_FAILED", "Unable to decrypt secret", "")
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
