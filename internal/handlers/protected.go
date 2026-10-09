package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/metrics"
	"github.com/kubeseal-ui/api/internal/policy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const maxRequestBody = 10 * 1024 * 1024

// ProtectedHandlers contains dependencies for authenticated API endpoints.
type ProtectedHandlers struct {
	Kubernetes      kubernetes.Client
	Crypto          *crypto.Wrapper
	EnableDecrypt   bool
	GitMappings     *policy.PolicyStore
	GitTransport    gitops.GitTransport
	SecurityEvents  SecurityEventSink
	idempotencyMu   sync.Mutex
	idempotencyKeys map[string]struct{}
}

// SecurityEventSink receives bounded audit records for sensitive operations.
type SecurityEventSink interface {
	EmitSecurityEvent(operation, subject, namespace, secret, key, mode, result, requestID string)
}

func (h *ProtectedHandlers) emitSecurityEvent(r *http.Request, operation, namespace, secret, key, mode, result string) {
	if h.SecurityEvents != nil {
		identity, _ := authmw.GetIdentity(r.Context())
		h.SecurityEvents.EmitSecurityEvent(operation, identity.Subject, namespace, secret, key, mode, result, requestID(r))
	}
	// The metric carries the bounded outcome only (operation, result);
	// namespace and secret names never become labels.
	metrics.RecordSecretOperation(operation, result)
}

// Bounded outcomes for sealed-secret operations. These are the only
// values the `result` label of kubeseal_ui_sealed_secret_operations_total
// and the security event stream may carry.
//
// They must reflect what actually happened. Emitting a constant value
// (previously the literal "attempt") makes success, failure, and denial
// indistinguishable in both the metric and the audit trail — which hides
// failures from alerting and makes the audit record useless for proving
// what a reveal did.
const (
	opResultSuccess        = "success"
	opResultDenied         = "denied"
	opResultDisabled       = "disabled"
	opResultInvalidRequest = "invalid_request"
	opResultNotFound       = "not_found"
	opResultConflict       = "conflict"
	opResultFailed         = "failed"
)

// NewProtectedHandlers constructs handlers for protected resources.
func NewProtectedHandlers(k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, idempotencyKeys: make(map[string]struct{})}
}

func NewProtectedHandlersWithGitOps(store *policy.PolicyStore, transport gitops.GitTransport, k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, GitMappings: store, GitTransport: transport, idempotencyKeys: make(map[string]struct{})}
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

// lookupManifest locates a Git manifest by identity using two-tier discovery
// (Option A): tier 1 reads the fast-path target rendered from the namespace's
// pathTemplate, tier 2 walks the repository tree for a SealedSecret matching
// the namespace and name.
//
// found=false with a nil error means the path is vacant — the documented
// new-file case. The returned snapshot is meaningful on that path too: it
// carries the branch head, which is what a BaseCommit check compares against
// and therefore what a new file must be built on. Tier 1's snapshot is kept
// when tier 2 also finds nothing, so the head is not lost to the fallback.
func (h *ProtectedHandlers) lookupManifest(ctx context.Context, mapping policy.GitMapping, target gitops.Target, namespace, name string) (gitops.ManifestSnapshot, bool, error) {
	snapshot, err := h.GitTransport.ReadManifest(ctx, target, mapping.AuthRef)
	if err == nil {
		return snapshot, true, nil
	}
	if !errors.Is(err, gitops.ErrNotFound) {
		return snapshot, false, err
	}

	found, searchErr := h.GitTransport.SearchManifest(ctx, mapping.Repository, mapping.Branch, namespace, name, mapping.AuthRef)
	if searchErr == nil {
		return found, true, nil
	}
	if !errors.Is(searchErr, gitops.ErrNotFound) {
		return snapshot, false, searchErr
	}
	return snapshot, false, nil
}

func (h *ProtectedHandlers) gitStatus(r *http.Request, namespace, name, liveYAML, baseCommit string) (map[string]any, error) {
	status := map[string]any{"managed": false, "in_sync_with_live": false, "drift": string(kubernetes.DriftUnknown)}
	if h.GitMappings == nil || h.GitTransport == nil {
		return status, nil
	}
	mapping, ok := h.GitMappings.GetGitMapping(namespace)
	if !ok {
		return status, nil
	}
	defaultPath := mapping.RenderPath(namespace, name)
	target := gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: defaultPath}
	status = map[string]any{
		"managed": true, "in_sync_with_live": false, "drift": string(kubernetes.DriftUnknown),
		"file_path": target.Path, "repository": target.Repository, "branch": target.Branch,
		"delivery_mode": string(mapping.Mode),
	}
	if target.Path == "" {
		return status, errors.New("invalid Git mapping")
	}

	snapshot, found, err := h.lookupManifest(r.Context(), mapping, target, namespace, name)
	if err != nil {
		return status, err
	}
	if !found {
		if liveYAML != "" {
			status["drift"] = "live_only"
		}
		return status, nil
	}

	// Discovered path
	target.Path = snapshot.Target.Path
	status["file_path"] = target.Path
	status["base_commit"] = snapshot.Commit

	if baseCommit != "" && snapshot.Commit != baseCommit {
		return status, &gitops.BaseCommitError{Expected: baseCommit, Actual: snapshot.Commit}
	}
	if liveYAML == "" {
		status["drift"] = "git_only"
		return status, nil
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
		status["drift"] = string(kubernetes.DriftSync)
		status["in_sync_with_live"] = true
		return status, nil
	}
	status["drift"] = string(kubernetes.DriftDiverged)
	return status, nil
}

func canonicalSealedSecret(manifest string) ([]byte, error) {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &m); err != nil {
		return nil, err
	}
	// Strip volatile Kubernetes runtime and GitOps tracking fields so canonical comparison accurately
	// compares spec and stable metadata without false divergences.
	delete(m, "status")
	if meta, ok := m["metadata"].(map[string]any); ok {
		delete(meta, "resourceVersion")
		delete(meta, "uid")
		delete(meta, "generation")
		delete(meta, "creationTimestamp")
		delete(meta, "managedFields")
		cleanAnnotations(meta)
		cleanLabels(meta)
	}
	if spec, ok := m["spec"].(map[string]any); ok {
		if tpl, ok := spec["template"].(map[string]any); ok {
			if tplMeta, ok := tpl["metadata"].(map[string]any); ok {
				delete(tplMeta, "creationTimestamp")
				cleanAnnotations(tplMeta)
				cleanLabels(tplMeta)
				if len(tplMeta) == 0 {
					delete(tpl, "metadata")
				}
			}
		}
	}
	return json.Marshal(m)
}

func cleanAnnotations(meta map[string]any) {
	ann, ok := meta["annotations"].(map[string]any)
	if !ok {
		return
	}
	for k := range ann {
		if strings.HasPrefix(k, "kubectl.kubernetes.io/") ||
			strings.HasPrefix(k, "argocd.argoproj.io/") ||
			strings.HasPrefix(k, "helm.sh/") ||
			strings.HasPrefix(k, "meta.helm.sh/") ||
			strings.HasPrefix(k, "fluxcd.io/") ||
			strings.HasPrefix(k, "kustomize.toolkit.fluxcd.io/") {
			delete(ann, k)
		}
	}
	if len(ann) == 0 {
		delete(meta, "annotations")
	}
}

func cleanLabels(meta map[string]any) {
	labels, ok := meta["labels"].(map[string]any)
	if !ok {
		return
	}
	for k := range labels {
		if strings.HasPrefix(k, "argocd.argoproj.io/") ||
			strings.HasPrefix(k, "helm.sh/") {
			delete(labels, k)
		}
	}
	if len(labels) == 0 {
		delete(meta, "labels")
	}
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

// GitPathsHandler returns the allowed target paths for namespaces the user has gitops:push access to.
// This enables the frontend to show a folder picker for seal operations.
func (h *ProtectedHandlers) GitPathsHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.MetadataRead) {
		return
	}
	if h.GitMappings == nil {
		writeError(w, r, http.StatusServiceUnavailable, "GITOPS_UNAVAILABLE", "GitOps not configured")
		return
	}
	
	// Get user's groups to determine which namespaces they have gitops:push access to
	identity, _ := authmw.GetIdentity(r.Context())
	userGroups := identity.Groups
	
	// Build capability set from user's groups
	var userCapabilities []policy.Capability
	if len(userGroups) > 0 {
		userCapabilities = h.GitMappings.CapabilitiesForGroups(userGroups)
	}
	
	// Check which namespaces user has gitops:push access to
	hasPush := make(map[string]bool)
	for _, cap := range userCapabilities {
		if cap == policy.GitOpsPush || cap == policy.GitOpsPropose {
			// User has push/propose capability - they can access all mapped namespaces
			// Per-namespace RBAC is enforced at seal time via IsPathAllowed
			hasPush["*"] = true
			break
		}
	}
	
	// For now, return all namespaces' allowedPaths (user's namespace access is controlled by RBAC on the secret itself)
	// The actual write is validated by IsPathAllowed against the specific namespace's mapping
	type nsPaths struct {
		Namespace    string   `json:"namespace"`
		DefaultPath  string   `json:"default_path"`
		AllowedPaths []string `json:"allowed_paths"`
		Repository   string   `json:"repository"`
		Branch       string   `json:"branch"`
		Mode         string   `json:"mode"`
	}
	
	var result []nsPaths
		for ns, mapping := range h.GitMappings.GetAllMappings() {
			result = append(result, nsPaths{
				Namespace:    ns,
				DefaultPath:  mapping.RenderPath(ns, ""),
				AllowedPaths: mapping.AllowedPaths,
				Repository:   mapping.Repository,
				Branch:       mapping.Branch,
				Mode:         string(mapping.Mode),
			})
		}
	
		jsonResponse(w, http.StatusOK, map[string]any{"namespaces": result})
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
			git = map[string]any{"managed": true, "in_sync_with_live": false, "drift": string(kubernetes.DriftUnknown)}
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
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	YAML       string `json:"yaml"`
	Scope      string `json:"scope"`
	TargetPath string `json:"target_path,omitempty"`
}

// EncryptHandler encrypts a Secret manifest without persisting it.
func (h *ProtectedHandlers) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	// The resource is named in the body rather than the URL, so these can only
	// be populated after the decode below. Every path that refuses before then
	// — an unauthenticated caller, or one without secret:seal — therefore
	// records an event with no namespace and no name. That is the honest
	// record: at the point of refusal nothing had been named yet, and parsing
	// untrusted input for a caller who cannot act on it would be the worse
	// trade.
	var namespace, name string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "seal", namespace, name, "", "", result) }()

	if !requireCapability(w, r, policy.SecretSeal) {
		result = opResultDenied
		return
	}
	if h.Crypto == nil {
		result = opResultDisabled
		writeError(w, r, http.StatusServiceUnavailable, "CRYPTO_UNAVAILABLE", "Crypto unavailable")
		return
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	}
	if r.ContentLength > maxRequestBody {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
		return
	}
	var req encryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			result = opResultInvalidRequest
			writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
			return
		}
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if req.Namespace == "" || req.Name == "" || req.YAML == "" || !validName(req.Namespace) || !validName(req.Name) {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	// Past validation the request names a resource, so the audit record can too.
	namespace, name = req.Namespace, req.Name

	// Resolve the mapped target once, so the vacancy gate below and the
	// response's base commit both use the same path. The helper writes its own
	// error response, so it reports the bounded outcome back through result.
	mapping, mapped, mappedPath, ok := h.resolveEncryptTarget(w, r, &req, &result)
	if !ok {
		return
	}

	scope := crypto.StrictScope
	if req.Scope != "" {
		if err := scope.Set(req.Scope); err != nil {
			result = opResultInvalidRequest
			writeError(w, r, http.StatusBadRequest, "INVALID_SCOPE", "Invalid scope")
			return
		}
	}
	// A cluster-wide SealedSecret can be decrypted in any namespace, so it
	// widens the blast radius beyond the caller's namespace mappings.
	// Crypto-wrapper contract: cluster-wide creation requires access:manage
	// on top of secret:seal.
	if scope == crypto.ClusterWideScope && !requireCapability(w, r, policy.AccessManage) {
		result = opResultDenied
		return
	}

	baseCommit := ""
	if mapped {
		// Checked before encrypting so a doomed request does no crypto work.
		baseCommit, ok = h.encryptTargetIsVacant(w, r, mapping, mappedPath, &req, &result)
		if !ok {
			return
		}
	}

	sealed, err := h.Crypto.EncryptYAML(r.Context(), req.YAML, req.Namespace, req.Name, scope)
	if err != nil {
		result = opResultFailed
		slog.Error("encrypt secret failed", "namespace", req.Namespace, "name", req.Name, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "ENCRYPTION_FAILED", "Unable to encrypt request")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"yaml": sealed, "base_commit": baseCommit})
	result = opResultSuccess
}

// resolveEncryptTarget decides which mapped file a new Secret would occupy and
// returns its mapping, the rendered path, and whether the path is a mapped one
// at all.
//
// mapped is false when the namespace has no mapping, when the mapping renders no
// path, or when there is no transport to read with. A namespace with no mapped
// path has nothing to occupy, so encrypt keeps working unmapped. It writes an
// error response and returns ok=false when the request itself cannot be
// satisfied — an unknown namespace or a target path the mapping does not allow —
// and reports that refusal's bounded outcome through result, because the caller
// has no other way to see which of the two it was.
func (h *ProtectedHandlers) resolveEncryptTarget(w http.ResponseWriter, r *http.Request, req *encryptRequest, result *string) (policy.GitMapping, bool, string, bool) {
	if req.TargetPath == "" {
		if h.GitMappings == nil || h.GitTransport == nil {
			return policy.GitMapping{}, false, "", true
		}
		mapping, ok := h.GitMappings.GetGitMapping(req.Namespace)
		if !ok {
			return policy.GitMapping{}, false, "", true
		}
		rendered := mapping.RenderPath(req.Namespace, req.Name)
		if rendered == "" {
			return policy.GitMapping{}, false, "", true
		}
		return mapping, true, rendered, true
	}

	if h.GitMappings == nil {
		*result = opResultDisabled
		writeError(w, r, http.StatusServiceUnavailable, "GITOPS_UNAVAILABLE", "GitOps not configured")
		return policy.GitMapping{}, false, "", false
	}
	mapping, ok := h.GitMappings.GetGitMapping(req.Namespace)
	if !ok {
		*result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "MAPPING_NOT_FOUND", "No Git mapping for namespace")
		return policy.GitMapping{}, false, "", false
	}
	if !mapping.IsPathAllowed(req.TargetPath, req.Namespace, req.Name) {
		// The response is a 400 because the client asked for the wrong thing,
		// but the refusal itself is the mapping's policy, so the outcome is
		// recorded as a denial: an audit that could not separate "tried to
		// write outside the granted paths" from "sent malformed JSON" would
		// not be worth keeping.
		*result = opResultDenied
		writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
		return policy.GitMapping{}, false, "", false
	}
	// No transport means nothing to read, so the caller's vacancy gate is
	// skipped. Without this the gate would call into a nil transport, because
	// `mapped` is what authorizes that call.
	if h.GitTransport == nil {
		return policy.GitMapping{}, false, "", true
	}
	return mapping, true, req.TargetPath, true
}

// encryptTargetIsVacant enforces the documented gate: the mapped target must be
// vacant. Creating under a name whose manifest already exists would silently
// replace it, which is what the separate create and edit flows exist to prevent.
//
// The vacant path still reports the branch head, and that head is the return
// value: BaseCommit is compared against the branch head, and no other endpoint
// yields one for a namespace that has no secrets yet. It writes an error
// response and returns ok=false on refusal, and reports that refusal's bounded
// outcome through result for the same reason resolveEncryptTarget does.
func (h *ProtectedHandlers) encryptTargetIsVacant(w http.ResponseWriter, r *http.Request, mapping policy.GitMapping, path string, req *encryptRequest, result *string) (string, bool) {
	target := gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path}
	snapshot, found, err := h.lookupManifest(r.Context(), mapping, target, req.Namespace, req.Name)
	if err != nil {
		*result = opResultFailed
		slog.Error("git lookup failed", "namespace", req.Namespace, "name", req.Name, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return "", false
	}
	if found {
		*result = opResultConflict
		writeError(w, r, http.StatusConflict, "PATH_OCCUPIED", "A manifest for this Secret already exists at the mapped path")
		return "", false
	}
	return snapshot.Commit, true
}

func validName(value string) bool {
	return len(validation.IsDNS1123Subdomain(value)) == 0
}

// DecryptHandler returns one requested key only after internal decryption.
func (h *ProtectedHandlers) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	// key is captured by the deferred emit and populated once the body is
	// parsed, so a decoded attempt records which key was requested.
	var key string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "reveal", namespace, name, key, "", result) }()

	if !requireCapability(w, r, policy.SecretDecrypt) {
		result = opResultDenied
		return
	}
	if !h.EnableDecrypt || h.Crypto == nil {
		result = opResultDisabled
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
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	key = strings.TrimSpace(req.Key)
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil || secret.YAML == "" {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	plain, err := h.Crypto.DecryptYAML(r.Context(), secret.YAML)
	if err != nil {
		result = opResultFailed
		slog.Error("decrypt sealed secret failed", "namespace", namespace, "name", name, "key", key, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "DECRYPTION_FAILED", "Unable to decrypt secret")
		return
	}
	value, ok := extractStringDataKey(plain, req.Key)
	if !ok {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "KEY_NOT_FOUND", "Key not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"key": req.Key, "value": value})
	result = opResultSuccess
}

// DiffHandler computes an encrypted before/after diff without persisting it.
func (h *ProtectedHandlers) DiffHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	// Diff decrypts the complete Secret internally, so it is audited like
	// reveal and patch even though it returns ciphertext only.
	var key string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "diff", namespace, name, key, "", result) }()

	if !requireCapability(w, r, policy.SecretSeal, policy.SecretDecrypt) {
		result = opResultDenied
		return
	}
	if !h.EnableDecrypt || h.Crypto == nil {
		result = opResultDisabled
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
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	key = strings.TrimSpace(req.Key)
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key")
		return
	}
	if !h.claimIdempotency(r) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "DUPLICATE_REQUEST", "Request already processed")
		return
	}
	op := crypto.ResealOp(req.Operation)
	if op != crypto.ResealReplace && op != crypto.ResealAdd && op != crypto.ResealDelete {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_OPERATION", "Invalid operation")
		return
	}
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil || secret.YAML == "" {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	after, err := h.Crypto.Reseal(r.Context(), secret.YAML, req.Key, req.Value, op)
	if err != nil {
		result = opResultFailed
		slog.Error("reseal secret failed", "namespace", namespace, "name", name, "key", req.Key, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"before": secret.YAML, "after": after, "key": req.Key, "base_commit": req.BaseCommit, "checksum": encryptedChecksum(after)})
	result = opResultSuccess
}

// ResealHandler mutates exactly one encrypted key.
func (h *ProtectedHandlers) ResealHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name, key := chi.URLParam(r, "namespace"), chi.URLParam(r, "name"), chi.URLParam(r, "key")
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "patch", namespace, name, key, "", result) }()

	if !requireCapability(w, r, policy.SecretSeal, policy.SecretDecrypt) {
		result = opResultDenied
		return
	}
	if !h.EnableDecrypt || h.Crypto == nil {
		result = opResultDisabled
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
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "MISSING_IDEMPOTENCY_KEY", "Missing Idempotency-Key")
		return
	}
	if !h.claimIdempotency(r) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "DUPLICATE_REQUEST", "Request already processed")
		return
	}
	op := crypto.ResealOp(req.Operation)
	if op != crypto.ResealReplace && op != crypto.ResealAdd && op != crypto.ResealDelete {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_OPERATION", "Invalid operation")
		return
	}
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil || secret.YAML == "" {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	git, gitErr := h.gitStatus(r, namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	sealed, err := h.Crypto.Reseal(r.Context(), secret.YAML, key, req.Value, op)
	if err != nil {
		result = opResultFailed
		slog.Error("reseal secret failed", "namespace", namespace, "name", name, "key", key, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"yaml": sealed, "checksum": encryptedChecksum(sealed), "diff_before": secret.YAML, "diff_after": sealed})
	result = opResultSuccess
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
