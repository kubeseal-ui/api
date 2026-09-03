package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const maxRequestBody = 10 * 1024 * 1024

// ProtectedHandlers contains dependencies for authenticated API endpoints.
type ProtectedHandlers struct {
	Kubernetes        kubernetes.Client
	Crypto            *crypto.Wrapper
	EnableDecrypt     bool
	GitMappings       *policy.PolicyStore
	GitTransport      gitops.GitTransport
	ProposalProviders map[string]gitops.ProposalProvider
	idempotencyMu     sync.Mutex
	idempotencyKeys   map[string]struct{}
}

// NewProtectedHandlers constructs handlers for protected resources.
func NewProtectedHandlers(k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, idempotencyKeys: make(map[string]struct{})}
}

func NewProtectedHandlersWithGitOps(store *policy.PolicyStore, transport gitops.GitTransport, k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, GitMappings: store, GitTransport: transport, ProposalProviders: make(map[string]gitops.ProposalProvider), idempotencyKeys: make(map[string]struct{})}
}

func (h *ProtectedHandlers) claimIdempotency(r *http.Request) bool {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		return false
	}
	id, _ := authmw.GetIdentity(r.Context())
	compound := id.Subject + "\x00" + key
	h.idempotencyMu.Lock()
	defer h.idempotencyMu.Unlock()
	if _, exists := h.idempotencyKeys[compound]; exists {
		return false
	}
	h.idempotencyKeys[compound] = struct{}{}
	return true
}

func requireCapability(w http.ResponseWriter, r *http.Request, required ...policy.Capability) bool {
	identity, ok := authmw.GetIdentity(r.Context())
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Unauthenticated")
		return false
	}
	for _, want := range required {
		found := false
		for _, got := range identity.Capabilities {
			if got == string(want) {
				found = true
				break
			}
		}
		if !found {
			writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
			return false
		}
	}
	return true
}

// SecretHandler returns encrypted metadata for one SealedSecret.
func (h *ProtectedHandlers) SecretHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.MetadataRead) {
		return
	}
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	if !validName(namespace) || !validName(name) {
		writeError(w, r, http.StatusBadRequest, "INVALID_RESOURCE_NAME", "Invalid namespace or name")
		return
	}
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil {
		if errors.Is(err, kubernetes.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
			return
		}
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, secret)
}

// NamespacesHandler lists namespaces visible to the API service account.
func (h *ProtectedHandlers) NamespacesHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.MetadataRead) {
		return
	}
	namespaces, err := h.Kubernetes.ListNamespaces(r.Context())
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"namespaces": namespaces})
}

// SecretsHandler lists SealedSecrets in a namespace.
func (h *ProtectedHandlers) SecretsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.MetadataRead) {
		return
	}
	namespace := r.URL.Query().Get("namespace")
	secrets, err := h.Kubernetes.ListSealedSecrets(r.Context(), namespace)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"secrets": secrets})
}

type encryptRequest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	YAML      string `json:"yaml"`
	Scope     string `json:"scope"`
}

// EncryptHandler encrypts a Secret manifest without persisting it.
func (h *ProtectedHandlers) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.SecretSeal) {
		return
	}
	if h.Crypto == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CRYPTO_UNAVAILABLE", "Crypto unavailable")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	if r.ContentLength > maxRequestBody {
		writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
		return
	}
	var req encryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
			return
		}
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if req.Namespace == "" || req.Name == "" || req.YAML == "" || !validName(req.Namespace) || !validName(req.Name) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	scope := crypto.StrictScope
	if req.Scope != "" {
		if err := scope.Set(req.Scope); err != nil {
			writeError(w, r, http.StatusBadRequest, "INVALID_SCOPE", "Invalid scope")
			return
		}
	}
	sealed, err := h.Crypto.EncryptYAML(r.Context(), req.YAML, req.Namespace, req.Name, scope)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "ENCRYPTION_FAILED", "Unable to encrypt request")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"yaml": sealed})
}

func validName(value string) bool {
	return len(validation.IsDNS1123Subdomain(value)) == 0
}

// DecryptHandler returns one requested key only after internal decryption.
func (h *ProtectedHandlers) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.SecretDecrypt) {
		return
	}
	if !h.EnableDecrypt || h.Crypto == nil {
		writeError(w, r, http.StatusForbidden, "DECRYPT_DISABLED", "Decrypt is disabled")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	var req struct {
		Key        string `json:"key"`
		BaseCommit string `json:"base_commit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Key) == "" || strings.TrimSpace(req.BaseCommit) == "" {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), chi.URLParam(r, "namespace"), chi.URLParam(r, "name"))
	if err != nil || secret.YAML == "" {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	plain, err := h.Crypto.DecryptYAML(r.Context(), secret.YAML)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "DECRYPTION_FAILED", "Unable to decrypt secret")
		return
	}
	value, ok := extractStringDataKey(plain, req.Key)
	if !ok {
		writeError(w, r, http.StatusNotFound, "KEY_NOT_FOUND", "Key not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"key": req.Key, "value": value})
}

// ResealHandler mutates exactly one encrypted key.
func (h *ProtectedHandlers) ResealHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.SecretSeal, policy.SecretDecrypt) {
		return
	}
	if !h.EnableDecrypt || h.Crypto == nil {
		writeError(w, r, http.StatusForbidden, "DECRYPT_DISABLED", "Decrypt is disabled")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	var req struct {
		Operation  string `json:"operation"`
		Value      string `json:"value"`
		BaseCommit string `json:"base_commit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.BaseCommit) == "" {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		writeError(w, r, http.StatusBadRequest, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key")
		return
	}
	op := crypto.ResealOp(req.Operation)
	if op != crypto.ResealReplace && op != crypto.ResealAdd && op != crypto.ResealDelete {
		writeError(w, r, http.StatusBadRequest, "INVALID_OPERATION", "Invalid operation")
		return
	}
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), chi.URLParam(r, "namespace"), chi.URLParam(r, "name"))
	if err != nil || secret.YAML == "" {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	sealed, err := h.Crypto.Reseal(r.Context(), secret.YAML, chi.URLParam(r, "key"), req.Value, op)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"yaml": sealed})
}

func extractStringDataKey(yamlText, key string) (string, bool) {
	var secret corev1.Secret
	if err := yaml.Unmarshal([]byte(yamlText), &secret); err != nil {
		return "", false
	}
	if value, ok := secret.StringData[key]; ok {
		return value, true
	}
	if value, ok := secret.Data[key]; ok {
		return string(value), true
	}
	return "", false
}
