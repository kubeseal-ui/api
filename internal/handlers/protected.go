package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	SecurityEvents    SecurityEventSink
	idempotencyMu     sync.Mutex
	idempotencyKeys   map[string]struct{}
}

// SecurityEventSink receives bounded audit records for sensitive operations.
type SecurityEventSink interface {
	EmitSecurityEvent(operation, subject, namespace, secret, key, mode, result, requestID string)
}

func (h *ProtectedHandlers) emitSecurityEvent(r *http.Request, operation, namespace, secret, key, mode, result string) {
	if h.SecurityEvents == nil {
		return
	}
	identity, _ := authmw.GetIdentity(r.Context())
	h.SecurityEvents.EmitSecurityEvent(operation, identity.Subject, namespace, secret, key, mode, result, requestID(r))
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

func (h *ProtectedHandlers) gitStatus(r *http.Request, namespace, name, liveYAML, baseCommit string) (map[string]any, error) {
	status := map[string]any{"managed": false, "drift": kubernetes.DriftUnknown}
	if h.GitMappings == nil || h.GitTransport == nil {
		return status, nil
	}
	mapping, ok := h.GitMappings.GetGitMapping(namespace)
	if !ok {
		return status, nil
	}
	target := gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: mapping.RenderPath(namespace, name)}
	status = map[string]any{
		"managed": true, "drift": kubernetes.DriftUnknown, "path": target.Path,
		"repository": target.Repository, "branch": target.Branch,
	}
	if target.Path == "" {
		return status, errors.New("invalid Git mapping")
	}
	snapshot, err := h.GitTransport.ReadManifest(r.Context(), target)
	if err != nil {
		return status, err
	}
	status["base_commit"] = snapshot.Commit
	if baseCommit != "" && snapshot.Commit != baseCommit {
		return status, &gitops.BaseCommitError{Expected: baseCommit, Actual: snapshot.Commit}
	}
	liveCanonical, err := canonicalSealedSecret(liveYAML)
	if err != nil {
		return status, err
	}
	gitCanonical, err := canonicalSealedSecret(string(snapshot.Content))
	if err != nil {
		return status, err
	}
	if bytes.Equal(liveCanonical, gitCanonical) {
		status["drift"] = kubernetes.DriftSync
		return status, nil
	}
	status["drift"] = kubernetes.DriftDiverged
	return status, nil
}

func canonicalSealedSecret(manifest string) ([]byte, error) {
	var value any
	if err := yaml.Unmarshal([]byte(manifest), &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func encryptedChecksum(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
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
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, "")
	if gitErr != nil {
		writeError(w, r, http.StatusConflict, "GIT_STATE_UNAVAILABLE", "Git source unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{
		"name": secret.Name, "namespace": secret.Namespace, "scope": secret.Scope,
		"keys": secret.Keys, "key_count": secret.KeyCount, "created_at": secret.CreatedAt,
		"git": git, "sealed_secret_yaml": secret.YAML,
	})
}

// NamespacesHandler lists namespaces visible to the API service account.
// When a PolicyStore is configured, each namespace includes its Git
// delivery mode and target repository so the UI can show managed vs
// unmanaged namespaces and adapt the editor workflow accordingly.
func (h *ProtectedHandlers) NamespacesHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.MetadataRead) {
		return
	}
	nsList, err := h.Kubernetes.ListNamespaces(r.Context())
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}
	// Enrich with Git mapping info if available.
	if h.GitMappings != nil {
		for i, ns := range nsList {
			mapping, ok := h.GitMappings.GetGitMapping(ns.Name)
			if ok {
				nsList[i].GitManaged = true
				nsList[i].DeliveryMode = string(mapping.Mode)
				nsList[i].GitRepository = mapping.Repository
			}
		}
	}
	jsonResponse(w, http.StatusOK, map[string]any{"namespaces": nsList})
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
	items := make([]map[string]any, 0, len(secrets))
	for i := range secrets {
		git, gitErr := h.gitStatus(r, secrets[i].Namespace, secrets[i].Name, secrets[i].YAML, "")
		if gitErr != nil {
			git = map[string]any{"managed": true, "drift": kubernetes.DriftUnknown}
		}
		items = append(items, map[string]any{
			"name": secrets[i].Name, "namespace": secrets[i].Namespace,
			"scope": secrets[i].Scope, "key_count": secrets[i].KeyCount,
			"created_at": secrets[i].CreatedAt, "git": git,
		})
	}
	jsonResponse(w, http.StatusOK, map[string]any{"secrets": items})
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
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	defer h.emitSecurityEvent(r, "reveal", namespace, name, "", "", "attempt")
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
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != kubernetes.DriftSync {
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
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

// DiffHandler computes an encrypted before/after diff without persisting it.
func (h *ProtectedHandlers) DiffHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	if !requireCapability(w, r, policy.SecretSeal, policy.SecretDecrypt) {
		return
	}
	if !h.EnableDecrypt || h.Crypto == nil {
		writeError(w, r, http.StatusForbidden, "DECRYPT_DISABLED", "Decrypt is disabled")
		return
	}
	var req struct {
		Key        string `json:"key"`
		Operation  string `json:"operation"`
		Value      string `json:"value"`
		BaseCommit string `json:"base_commit"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil || strings.TrimSpace(req.Key) == "" || strings.TrimSpace(req.BaseCommit) == "" {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		writeError(w, r, http.StatusBadRequest, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key")
		return
	}
	if !h.claimIdempotency(r) {
		writeError(w, r, http.StatusConflict, "DUPLICATE_REQUEST", "Request already processed")
		return
	}
	op := crypto.ResealOp(req.Operation)
	if op != crypto.ResealReplace && op != crypto.ResealAdd && op != crypto.ResealDelete {
		writeError(w, r, http.StatusBadRequest, "INVALID_OPERATION", "Invalid operation")
		return
	}
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil || secret.YAML == "" {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != kubernetes.DriftSync {
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	after, err := h.Crypto.Reseal(r.Context(), secret.YAML, req.Key, req.Value, op)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"before": secret.YAML, "after": after, "key": req.Key, "base_commit": req.BaseCommit, "checksum": encryptedChecksum(after)})
}

// ResealHandler mutates exactly one encrypted key.
func (h *ProtectedHandlers) ResealHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name, key := chi.URLParam(r, "namespace"), chi.URLParam(r, "name"), chi.URLParam(r, "key")
	defer h.emitSecurityEvent(r, "patch", namespace, name, key, "", "attempt")
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
	if !h.claimIdempotency(r) {
		writeError(w, r, http.StatusConflict, "DUPLICATE_REQUEST", "Request already processed")
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
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != kubernetes.DriftSync {
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	sealed, err := h.Crypto.Reseal(r.Context(), secret.YAML, chi.URLParam(r, "key"), req.Value, op)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"yaml": sealed, "checksum": encryptedChecksum(sealed), "diff_before": secret.YAML, "diff_after": sealed})
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
