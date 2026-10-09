package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

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
	idempotency     *idempotencyStore
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
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, idempotency: newIdempotencyStore()}
}

func NewProtectedHandlersWithGitOps(store *policy.PolicyStore, transport gitops.GitTransport, k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, GitMappings: store, GitTransport: transport, idempotency: newIdempotencyStore()}
}

// idempotencyKey is the Idempotency-Key namespaced by the subject that sent it,
// so one caller cannot spend or block another's key. Empty when the header is
// absent.
func (h *ProtectedHandlers) idempotencyKey(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		return ""
	}
	id, _ := authmw.GetIdentity(r.Context())
	return id.Subject + "\x00" + key
}

// claimIdempotency reports whether this request may proceed, or whether it
// repeats one already claimed by the same subject. It is for endpoints that
// only need to refuse a duplicate; delivery endpoints use beginDelivery so a
// retry is answered with the original outcome instead.
func (h *ProtectedHandlers) claimIdempotency(r *http.Request) bool {
	key := h.idempotencyKey(r)
	if key == "" {
		return false
	}
	return h.idempotency.claim(key)
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

// requestTransport is the Git transport for one request: the configured one,
// wrapped so every read it serves comes from a single per-branch snapshot.
//
// Build it once per request and thread it through, rather than reaching for
// h.GitTransport at each read. A namespace listing resolves drift for every
// Secret it returns — a templated path first, then a tree walk when that path
// is vacant — and against a real remote each of those reads is a network fetch.
// One snapshot turns that from one fetch per Secret into one fetch per branch.
//
// The wrapper must not outlive the request: it answers from the head it read at
// the start, and a BaseCommit check against a head older than the request would
// let a conflicting push through. That is why this is a per-request value and
// not a field on the handler.
func (h *ProtectedHandlers) requestTransport() gitops.GitTransport {
	if h.GitTransport == nil {
		return nil
	}
	return gitops.NewSnapshotTransport(h.GitTransport)
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
func (h *ProtectedHandlers) lookupManifest(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, target gitops.Target, namespace, name string) (gitops.ManifestSnapshot, bool, error) {
	snapshot, err := transport.ReadManifest(ctx, target, mapping.AuthRef)
	if err == nil {
		return snapshot, true, nil
	}
	if !errors.Is(err, gitops.ErrNotFound) {
		return snapshot, false, err
	}

	found, searchErr := transport.SearchManifest(ctx, mapping.Repository, mapping.Branch, namespace, name, mapping.AuthRef)
	if searchErr == nil {
		return found, true, nil
	}
	if !errors.Is(searchErr, gitops.ErrNotFound) {
		return snapshot, false, searchErr
	}
	return snapshot, false, nil
}

// gitStatus resolves a Secret's Git state through the request's transport, so
// that resolving it for thirty Secrets in one listing costs one fetch per
// branch rather than one per Secret. See requestTransport.
func (h *ProtectedHandlers) gitStatus(ctx context.Context, transport gitops.GitTransport, namespace, name, liveYAML, baseCommit string) (map[string]any, error) {
	status := map[string]any{"managed": false, "in_sync_with_live": false, "drift": string(kubernetes.DriftUnknown)}
	if h.GitMappings == nil || transport == nil {
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

	snapshot, found, err := h.lookupManifest(ctx, transport, mapping, target, namespace, name)
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

// gitopsAnnotationPrefixes are the annotation namespaces that record how a
// manifest was applied rather than what it is. They are stripped both from a
// SealedSecret the API compares against Git and from a Secret it adopts, so the
// two agree on what a manifest of this product may carry. The one that makes
// this concrete: `kubectl get -o yaml` emits
// kubectl.kubernetes.io/last-applied-configuration, which holds the entire
// object as JSON — sealed into the file it would be pure noise, and it would
// carry back every field the normalizer is about to strip.
var gitopsAnnotationPrefixes = []string{
	"kubectl.kubernetes.io/",
	"argocd.argoproj.io/",
	"helm.sh/",
	"meta.helm.sh/",
	"fluxcd.io/",
	"kustomize.toolkit.fluxcd.io/",
}

// gitopsLabelPrefixes are the label namespaces that record which tool owns a
// manifest. Ownership is the delivering tool's business, not the Secret's.
var gitopsLabelPrefixes = []string{
	"argocd.argoproj.io/",
	"helm.sh/",
}

// runtimeMetadataFields are assigned by the API server to one live object.
// Carrying them into a manifest records something that was never true of the
// file, and the next apply would reject or fight them.
var runtimeMetadataFields = []string{
	"uid", "resourceVersion", "generation", "creationTimestamp", "managedFields", "selfLink",
}

func cleanAnnotations(meta map[string]any) {
	ann, ok := meta["annotations"].(map[string]any)
	if !ok {
		return
	}
	for k := range ann {
		if hasAnyPrefix(k, gitopsAnnotationPrefixes) {
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
		if hasAnyPrefix(k, gitopsLabelPrefixes) {
			delete(labels, k)
		}
	}
	if len(labels) == 0 {
		delete(meta, "labels")
	}
}

func hasAnyPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

// normalizeSecretYAML reduces a manifest to the desired state of a Secret.
//
// This is what makes adopting a live Secret possible without a new Kubernetes
// permission: the operator's own `kubectl get secret -o yaml` is the source, and
// the API only ever sees the content the operator chose to paste. It is applied
// to every seal request, typed manifests included, so the create path has one
// shape rather than two.
//
// What it removes is everything that describes the object's life rather than its
// content — status, the server-assigned metadata, a live owner reference, and the
// annotations and labels that record which tool applied it. What it refuses is a
// manifest that is not a Secret, or one that names a different resource than the
// request: sealing Secret A's content under Secret B's name is a silent,
// confusing failure, and it is the likeliest mistake in a copy-paste flow.
func normalizeSecretYAML(secretYAML, namespace, name string) (string, error) {
	var manifest map[string]any
	if err := yaml.Unmarshal([]byte(secretYAML), &manifest); err != nil {
		return "", fmt.Errorf("not a valid YAML document: %w", err)
	}
	if len(manifest) == 0 {
		return "", errors.New("empty manifest")
	}
	if kind, isString := manifest["kind"].(string); !isString || kind != "Secret" {
		return "", fmt.Errorf("expected a Secret, got kind %q", kind)
	}

	meta, ok := manifest["metadata"].(map[string]any)
	if !ok {
		meta = map[string]any{}
		manifest["metadata"] = meta
	}
	for _, field := range runtimeMetadataFields {
		delete(meta, field)
	}
	// Adoption copies a Secret's content, not its garbage-collection
	// relationship to whatever created it. A manifest that arrived owning
	// itself would be a claim about a cluster the file does not live in.
	delete(meta, "ownerReferences")
	delete(manifest, "status")
	cleanAnnotations(meta)
	cleanLabels(meta)

	if declared, isString := meta["name"].(string); isString && declared != "" && declared != name {
		return "", fmt.Errorf("manifest names %q, but this request names %q", declared, name)
	}
	if declared, isString := meta["namespace"].(string); isString && declared != "" && declared != namespace {
		return "", fmt.Errorf("manifest is for namespace %q, but this request is for %q", declared, namespace)
	}

	normalized, err := yaml.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("re-encode manifest: %w", err)
	}
	return string(normalized), nil
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
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, "")
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
	// One transport for the whole listing: every Secret here is resolved
	// against the same branches, and the shared snapshot is what keeps this
	// loop from turning into one Git fetch per Secret.
	transport := h.requestTransport()
	for i := range secrets {
		git, gitErr := h.gitStatus(r.Context(), transport, secrets[i].Namespace, secrets[i].Name, secrets[i].YAML, "")
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

	// The submitted manifest is reduced to desired state before anything reads
	// it: this is the shape a live Secret arrives in when it is adopted by
	// pasting `kubectl get secret -o yaml`, and applying it to typed manifests
	// too keeps the create path to one shape rather than two. A manifest that is
	// not a Secret is the most basic thing a request can get wrong, so it is
	// refused before any policy resolution or Git read.
	normalized, err := normalizeSecretYAML(req.YAML, req.Namespace, req.Name)
	if err != nil {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Manifest is not a Kubernetes Secret for this name and namespace")
		return
	}
	req.YAML = normalized

	// Resolve the mapped target once, so the vacancy gate below and the
	// response's base commit both use the same path. The helper writes its own
	// error response, so it reports the bounded outcome back through result.
	mapping, mapped, mappedPath, ok := h.resolveEncryptTarget(w, r, &req, &result)
	if !ok {
		return
	}

	scope := crypto.StrictScope
	if req.Scope != "" {
		if err = scope.Set(req.Scope); err != nil {
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
	snapshot, found, err := h.lookupManifest(r.Context(), h.requestTransport(), mapping, target, req.Namespace, req.Name)
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
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, req.BaseCommit)
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

// maxBatchKeys bounds one reviewed change. It matches the documented hard
// maximum of 400 keys in a Secret, so the largest Secret the product accepts
// can still be rewritten in a single batch rather than falling back to the
// per-key flow this replaced.
const maxBatchKeys = 400

// mutationRequest is one entry change as it arrives on the wire, shared by the
// diff and patch endpoints so the two cannot accept different shapes.
type mutationRequest struct {
	Key       string `json:"key"`
	Operation string `json:"operation"`
	Value     string `json:"value"`
}

// parseMutations validates a request's mutations and translates them into the
// crypto layer's type.
//
// The key names are returned sorted and comma-joined for the security event.
// Sorting is what makes the audit record a function of the change rather than
// of the JSON ordering the client happened to use, so the same batch always
// produces the same event. The join is bounded by maxBatchKeys, which is what
// keeps that field finite.
//
// Only the checks that need no decryption happen here — key naming and
// operation. Whether a key exists is not knowable until the Secret is decrypted
// inside the crypto layer, which reports those refusals as
// crypto.ErrInvalidMutation so the handler can still answer 400 rather than
// blaming the backend.
func parseMutations(mutations []mutationRequest) ([]crypto.Mutation, string, error) {
	if len(mutations) == 0 {
		return nil, "", errors.New("no mutations given")
	}
	if len(mutations) > maxBatchKeys {
		return nil, "", errors.New("too many mutations in one batch")
	}
	out := make([]crypto.Mutation, 0, len(mutations))
	keys := make([]string, 0, len(mutations))
	for _, m := range mutations {
		key := strings.TrimSpace(m.Key)
		if key == "" {
			return nil, "", errors.New("mutation has an empty key")
		}
		op := crypto.ResealOp(m.Operation)
		if op != crypto.ResealReplace && op != crypto.ResealAdd && op != crypto.ResealDelete {
			return nil, "", errors.New("invalid operation")
		}
		out = append(out, crypto.Mutation{Key: key, Value: m.Value, Op: op})
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return out, strings.Join(keys, ","), nil
}

// mutationSummary reports which keys a batch touches and how, without echoing
// the values.
//
// The caller already holds the values it sent, so returning them would add
// nothing — and it would put plaintext into a response body in a flow whose
// entire design is that only ciphertext crosses the boundary. The review
// response is meant to confirm what will change, not to repeat the secret back.
func mutationSummary(mutations []mutationRequest) []map[string]string {
	out := make([]map[string]string, 0, len(mutations))
	for _, m := range mutations {
		out = append(out, map[string]string{"key": strings.TrimSpace(m.Key), "operation": m.Operation})
	}
	return out
}

// DiffHandler computes an encrypted before/after diff for a batch of key
// changes without persisting anything.
func (h *ProtectedHandlers) DiffHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	// Diff decrypts the complete Secret internally, so it is audited like
	// reveal and patch even though it returns ciphertext only. changedKeys is
	// populated once the body is parsed and names every key the batch touches.
	var changedKeys string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "diff", namespace, name, changedKeys, "", result) }()

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
		Mutations  []mutationRequest `json:"mutations"`
		BaseCommit string            `json:"base_commit"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil || strings.TrimSpace(req.BaseCommit) == "" {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	// Everything refusable without decrypting is checked before the idempotency
	// key is spent, so a request that was never going to succeed cannot hold the
	// key against a corrected retry that reuses it.
	mutations, batchKeys, err := parseMutations(req.Mutations)
	if err != nil {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	changedKeys = batchKeys
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
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil || secret.YAML == "" {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	after, err := h.Crypto.ResealMany(r.Context(), secret.YAML, mutations)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidMutation) {
			result = opResultInvalidRequest
			writeError(w, r, http.StatusBadRequest, "INVALID_MUTATION", "Invalid mutation")
			return
		}
		result = opResultFailed
		slog.Error("reseal secret failed", "namespace", namespace, "name", name, "keys", changedKeys, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]any{"before": secret.YAML, "after": after, "mutations": mutationSummary(req.Mutations), "base_commit": req.BaseCommit, "checksum": encryptedChecksum(after)})
	result = opResultSuccess
}

// ResealHandler applies a batch of key mutations to one SealedSecret and
// returns the resealed manifest. It is the confirmed half of the flow whose
// diff half is DiffHandler: the caller reviews the ciphertext diff, then sends
// the same batch here to have it sealed.
//
// The key is named in the body rather than the URL, because a batch has no
// single key to put in a path. The previous one-key-per-request shape needed
// four round trips to change four keys, each with its own decrypt, reseal,
// review, and commit.
func (h *ProtectedHandlers) ResealHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	// populated once the body is parsed, so the audit record names every key
	// the patch touched.
	var changedKeys string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "patch", namespace, name, changedKeys, "", result) }()

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
		Mutations  []mutationRequest `json:"mutations"`
		BaseCommit string            `json:"base_commit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.BaseCommit) == "" {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	mutations, batchKeys, err := parseMutations(req.Mutations)
	if err != nil {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	changedKeys = batchKeys
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
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil || secret.YAML == "" {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Not found")
		return
	}
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, req.BaseCommit)
	if gitErr != nil || git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	sealed, err := h.Crypto.ResealMany(r.Context(), secret.YAML, mutations)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidMutation) {
			result = opResultInvalidRequest
			writeError(w, r, http.StatusBadRequest, "INVALID_MUTATION", "Invalid mutation")
			return
		}
		result = opResultFailed
		slog.Error("reseal secret failed", "namespace", namespace, "name", name, "keys", changedKeys, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to reseal secret")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]any{"yaml": sealed, "checksum": encryptedChecksum(sealed), "diff_before": secret.YAML, "diff_after": sealed, "mutations": mutationSummary(req.Mutations)})
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
