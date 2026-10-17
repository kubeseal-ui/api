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
	"reflect"
	"sort"
	"strings"
	"time"

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

// decodeJSONBody enforces the body limit while reading, so an oversized body answers 413 on every route.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if r.ContentLength > maxRequestBody {
		writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return false
	}
	return true
}

type ProtectedHandlers struct {
	Kubernetes     kubernetes.Client
	Crypto         *crypto.Wrapper
	EnableDecrypt  bool
	GitMappings    *policy.PolicyStore
	GitTransport   gitops.GitTransport
	SecurityEvents SecurityEventSink
	idempotency    *idempotencyStore
}

type SecurityEventSink interface {
	EmitSecurityEvent(operation, subject, namespace, secret, key, mode, result, requestID string)
}

func (h *ProtectedHandlers) emitSecurityEvent(r *http.Request, operation, namespace, secret, key, mode, result string) {
	if h.SecurityEvents != nil {
		identity, _ := authmw.GetIdentity(r.Context())
		h.SecurityEvents.EmitSecurityEvent(operation, identity.Subject, namespace, secret, key, mode, result, requestID(r))
	}
	// The metric carries the bounded outcome only; namespace and secret names never become labels.
	metrics.RecordSecretOperation(operation, result)
}

// Bounded outcomes: the only values the operations_total result label and audit stream may carry.
const (
	opResultSuccess        = "success"
	opResultDenied         = "denied"
	opResultDisabled       = "disabled"
	opResultInvalidRequest = "invalid_request"
	opResultNotFound       = "not_found"
	opResultConflict       = "conflict"
	opResultFailed         = "failed"
)

// Degraded: the listing answered with less than asked; alerting on it is how a Git outage shows.
const opResultDegraded = "degraded"

func NewProtectedHandlers(k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, idempotency: newIdempotencyStore()}
}

func NewProtectedHandlersWithGitOps(store *policy.PolicyStore, transport gitops.GitTransport, k8s kubernetes.Client, cryptoWrapper *crypto.Wrapper, enableDecrypt bool) *ProtectedHandlers {
	return &ProtectedHandlers{Kubernetes: k8s, Crypto: cryptoWrapper, EnableDecrypt: enableDecrypt, GitMappings: store, GitTransport: transport, idempotency: newIdempotencyStore()}
}

// idempotencyKey is the header key namespaced by subject, so one caller cannot spend another's.
func (h *ProtectedHandlers) idempotencyKey(r *http.Request) string {
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		return ""
	}
	id, _ := authmw.GetIdentity(r.Context())
	return id.Subject + "\x00" + key
}

// claimIdempotency: delivery endpoints use beginDelivery instead, so a retry gets the original outcome.
func (h *ProtectedHandlers) claimIdempotency(r *http.Request) bool {
	key := h.idempotencyKey(r)
	if key == "" {
		return false
	}
	return h.idempotency.claim(key)
}

// capabilityDeniedMessage names the missing capability so a 403 maps to the grant to fix.
func capabilityDeniedMessage(want policy.Capability) string {
	return "Access denied: missing capability " + string(want)
}

// requireCapability: AnyNamespace is for platform checks; a request that cannot name a namespace uses hasCapabilityAnywhere.
func requireCapability(w http.ResponseWriter, r *http.Request, namespace string, required ...policy.Capability) bool {
	identity, ok := authmw.GetIdentity(r.Context())
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Unauthenticated")
		return false
	}
	for _, want := range required {
		if !identity.HasCapabilityIn(namespace, string(want)) {
			writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", capabilityDeniedMessage(want))
			return false
		}
	}
	return true
}

// hasCapabilityAnywhere gates requests spanning namespaces; per-namespace decisions happen after.
func hasCapabilityAnywhere(w http.ResponseWriter, r *http.Request, required ...policy.Capability) bool {
	identity, ok := authmw.GetIdentity(r.Context())
	if !ok {
		writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Unauthenticated")
		return false
	}
	for _, want := range required {
		if !identity.HasCapabilityAnywhere(string(want)) {
			writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", capabilityDeniedMessage(want))
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// requestTransport wraps the configured transport in a per-request snapshot; it must not outlive the request.
func (h *ProtectedHandlers) requestTransport() gitops.GitTransport {
	if h.GitTransport == nil {
		return nil
	}
	return gitops.NewSnapshotTransport(h.GitTransport)
}

// lookupManifest: two-tier discovery; found=false means vacant, with tier 1's snapshot kept for its branch head.
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

// mappedFileText reads a file as Git holds it, served from the request's snapshot.
func (h *ProtectedHandlers) mappedFileText(ctx context.Context, transport gitops.GitTransport, namespace, path string) (string, error) {
	if h.GitMappings == nil || transport == nil {
		return "", errors.New("no Git mapping for this namespace")
	}
	mapping, ok := h.GitMappings.GetGitMapping(namespace)
	if !ok {
		return "", errors.New("no Git mapping for this namespace")
	}
	target := gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path}
	snapshot, err := transport.ReadManifest(ctx, target, mapping.AuthRef)
	if err != nil {
		return "", err
	}
	return string(snapshot.Content), nil
}

// gitStatus resolves a Secret's Git state through the request snapshot; withHistory and withGitText cost extra reads, so listings skip them.
func (h *ProtectedHandlers) gitStatus(ctx context.Context, transport gitops.GitTransport, namespace, name, liveYAML, baseCommit string, withHistory, withGitText bool) (map[string]any, error) {
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
		// The branch head is what lets the sync endpoint create a live_only file; dropping it contradicted can_sync.
		if snapshot.Commit != "" {
			status["base_commit"] = snapshot.Commit
		}
		if liveYAML != "" {
			status["drift"] = "live_only"
		}
		return status, nil
	}

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
	liveDoc, err := canonicalDocument(liveYAML)
	if err != nil {
		return status, err
	}
	gitDoc, err := canonicalDocument(string(snapshot.Content))
	if err != nil {
		return status, err
	}
	liveCanonical, err := json.Marshal(liveDoc)
	if err != nil {
		return status, err
	}
	gitCanonical, err := json.Marshal(gitDoc)
	if err != nil {
		return status, err
	}
	if bytes.Equal(liveCanonical, gitCanonical) {
		status["drift"] = string(kubernetes.DriftSync)
		status["in_sync_with_live"] = true
		return status, nil
	}
	status["drift"] = string(kubernetes.DriftDiverged)
	reason, fields := driftReason(liveDoc, gitDoc)
	status["drift_reason"] = reason
	if len(fields) > 0 {
		status["drift_fields"] = fields
	}
	// Diverged is the only state that offers a sync, so the copy it replaces travels with the drift.
	if withGitText {
		status["git_file_yaml"] = string(snapshot.Content)
	}
	if withHistory && h.gitMovedPastLive(ctx, transport, mapping, target, liveCanonical) {
		status["git_moved_ahead"] = true
	}
	return status, nil
}

// refuseGitRead: a failed read is never reported as drift — conflict, timeout, and unavailable are distinct outcomes.
func refuseGitRead(w http.ResponseWriter, r *http.Request, err error) string {
	var base *gitops.BaseCommitError
	switch {
	case errors.As(err, &base):
		writeError(w, r, http.StatusConflict, "BASE_COMMIT_CONFLICT", "Base commit conflict")
		return opResultConflict
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeError(w, r, http.StatusGatewayTimeout, "TIMEOUT", "The request exceeded the server's time limit")
		return opResultFailed
	default:
		writeError(w, r, http.StatusConflict, "GIT_STATE_UNAVAILABLE", "Git source unavailable")
		return opResultFailed
	}
}

// gitMovedPastLive: true when live matches the file's previous version; every uncertainty answers false.
func (h *ProtectedHandlers) gitMovedPastLive(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, target gitops.Target, liveCanonical []byte) bool {
	history, ok := transport.(gitops.ManifestHistory)
	if !ok {
		return false
	}
	previous, err := history.PreviousManifest(ctx, target, mapping.AuthRef)
	if err != nil {
		return false
	}
	previousCanonical, err := canonicalSealedSecret(string(previous))
	if err != nil {
		return false
	}
	return bytes.Equal(liveCanonical, previousCanonical)
}

func canonicalSealedSecret(manifest string) ([]byte, error) {
	m, err := canonicalDocument(manifest)
	if err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// canonicalDocument: the stripping lives in the kubernetes package, so one rule covers both sides.
func canonicalDocument(manifest string) (map[string]any, error) {
	return kubernetes.CanonicalManifest(manifest)
}

// Most decisive first; identity is the one a sync cannot resolve.
const (
	driftReasonIdentity   = "identity"
	driftReasonKeys       = "keys"
	driftReasonCiphertext = "ciphertext"
	driftReasonTemplate   = "template"
	driftReasonMetadata   = "metadata"
)

// driftReason names the most decisive differing category; the field list is never narrowed to it, and it reads ciphertext only.
func driftReason(live, git map[string]any) (string, []string) {
	var fields []string
	differingPaths(live, git, "", &fields)
	sort.Strings(fields)

	switch {
	case identityDiffers(live, git):
		return driftReasonIdentity, fields
	case !reflect.DeepEqual(specSection(live, "encryptedData"), specSection(git, "encryptedData")):
		// Sealing is not deterministic, so key names decide between separate encryptions and an added key.
		if encryptedKeyNamesDiffer(live, git) {
			return driftReasonKeys, fields
		}
		return driftReasonCiphertext, fields
	case !reflect.DeepEqual(specSection(live, "template"), specSection(git, "template")):
		return driftReasonTemplate, fields
	}
	return driftReasonMetadata, fields
}

// identityDiffers is true only when both sides declare a name and disagree.
func identityDiffers(live, git map[string]any) bool {
	liveName, liveOK := nestedString(live, "metadata", "name")
	gitName, gitOK := nestedString(git, "metadata", "name")
	return liveOK && gitOK && liveName != gitName
}

func encryptedKeyNamesDiffer(live, git map[string]any) bool {
	liveKeys, liveIsMap := specSection(live, "encryptedData").(map[string]any)
	gitKeys, gitIsMap := specSection(git, "encryptedData").(map[string]any)
	// One side carrying the section is itself a key-name difference.
	if liveIsMap != gitIsMap {
		return true
	}
	if len(liveKeys) != len(gitKeys) {
		return true
	}
	for key := range liveKeys {
		if _, ok := gitKeys[key]; !ok {
			return true
		}
	}
	return false
}

// specSection distinguishes a missing section from an empty one that was stripped.
func specSection(doc map[string]any, field string) any {
	spec, ok := doc["spec"].(map[string]any)
	if !ok {
		return nil
	}
	return spec[field]
}

func nestedString(doc map[string]any, path ...string) (string, bool) {
	var current any = doc
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current, ok = m[key]
		if !ok {
			return "", false
		}
	}
	value, ok := current.(string)
	return value, ok && value != ""
}

// differingPaths reports every differing leaf path; one-sided sections are descended into, not reported whole.
func differingPaths(a, b any, prefix string, out *[]string) {
	aMap, aIsMap := a.(map[string]any)
	bMap, bIsMap := b.(map[string]any)
	switch {
	case aIsMap && bIsMap:
		for key, aValue := range aMap {
			differingPaths(aValue, bMap[key], joinPath(prefix, key), out)
		}
		for key, bValue := range bMap {
			if _, ok := aMap[key]; !ok {
				differingPaths(nil, bValue, joinPath(prefix, key), out)
			}
		}
	case aIsMap:
		for key, aValue := range aMap {
			differingPaths(aValue, nil, joinPath(prefix, key), out)
		}
	case bIsMap:
		for key, bValue := range bMap {
			differingPaths(nil, bValue, joinPath(prefix, key), out)
		}
	default:
		if !reflect.DeepEqual(a, b) {
			*out = append(*out, prefix)
		}
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// normalizeSecretYAML reduces any manifest to a Secret's desired state and refuses one naming a different resource.
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
	// Adoption copies content, not ownership: a self-owning manifest claims another cluster.
	delete(meta, "ownerReferences")
	delete(manifest, "status")
	kubernetes.CleanMetadata(meta)

	if declared, isString := meta["name"].(string); isString && declared != "" && declared != name {
		return "", fmt.Errorf("manifest names %q, but this request names %q", declared, name)
	}
	if declared, isString := meta["namespace"].(string); isString && declared != "" && declared != namespace {
		return "", fmt.Errorf("manifest is for namespace %q, but this request is for %q", declared, namespace)
	}

	// Invalid keys would surface as drift after delivery; refusing here keeps the failure at seal time.
	for _, field := range []string{"data", "stringData"} {
		entries, ok := manifest[field].(map[string]any)
		if !ok {
			continue
		}
		for key := range entries {
			if msgs := validation.IsConfigMapKey(key); len(msgs) > 0 {
				return "", fmt.Errorf("%s key %q is not a valid Secret key: %s", field, key, msgs[0])
			}
		}
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
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	if !requireCapability(w, r, namespace, policy.MetadataRead) {
		return
	}
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
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, "", true, true)
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

// NamespacesHandler lists the namespaces this caller may read, each with its Git delivery mode and repository.
func (h *ProtectedHandlers) NamespacesHandler(w http.ResponseWriter, r *http.Request) {
	// The gate is "may read somewhere"; the filter below decides which namespaces.
	if !hasCapabilityAnywhere(w, r, policy.MetadataRead) {
		return
	}
	nsList, err := h.Kubernetes.ListNamespaces(r.Context())
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}
	identity, _ := authmw.GetIdentity(r.Context())
	visible := nsList[:0]
	for _, ns := range nsList {
		caps := identity.CapabilitiesFor(ns.Name)
		if !containsString(caps, string(policy.MetadataRead)) {
			continue
		}
		ns.Capabilities = caps
		if h.GitMappings != nil {
			if mapping, ok := h.GitMappings.GetGitMapping(ns.Name); ok {
				ns.GitManaged = true
				ns.DeliveryMode = string(mapping.Mode)
				ns.GitRepository = mapping.Repository
			}
		}
		visible = append(visible, ns)
	}
	jsonResponse(w, http.StatusOK, map[string]any{"namespaces": visible})
}

// GitPathsHandler returns allowed target paths per readable namespace; templates travel raw (no name to render) and AllowedPaths are directories.
func (h *ProtectedHandlers) GitPathsHandler(w http.ResponseWriter, r *http.Request) {
	if !hasCapabilityAnywhere(w, r, policy.MetadataRead) {
		return
	}
	if h.GitMappings == nil {
		writeError(w, r, http.StatusServiceUnavailable, "GITOPS_UNAVAILABLE", "GitOps not configured")
		return
	}

	// Grants were resolved once at session read; re-asking the store would be a second resolution path.
	identity, _ := authmw.GetIdentity(r.Context())

	type nsPaths struct {
		Namespace    string   `json:"namespace"`
		PathTemplate string   `json:"path_template"`
		AllowedPaths []string `json:"allowed_paths"`
		Repository   string   `json:"repository"`
		Branch       string   `json:"branch"`
		Mode         string   `json:"mode"`
	}

	// Unreadable namespaces are not destinations; the wildcard mapping stays as every unmapped namespace's fallback.
	result := make([]nsPaths, 0)
	for ns, mapping := range h.GitMappings.GetAllMappings() {
		if ns != policy.AnyNamespace && !containsString(identity.CapabilitiesFor(ns), string(policy.MetadataRead)) {
			continue
		}
		result = append(result, nsPaths{
			Namespace:    ns,
			PathTemplate: mapping.PathTemplate,
			AllowedPaths: mapping.AllowedPaths,
			Repository:   mapping.Repository,
			Branch:       mapping.Branch,
			Mode:         string(mapping.Mode),
		})
	}

	jsonResponse(w, http.StatusOK, map[string]any{"namespaces": result})
}

func (h *ProtectedHandlers) SecretsHandler(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		// A question about where the caller holds metadata:read; the listing below is filtered.
		if !hasCapabilityAnywhere(w, r, policy.MetadataRead) {
			return
		}
	} else if !requireCapability(w, r, namespace, policy.MetadataRead) {
		return
	}
	secrets, err := h.Kubernetes.ListSealedSecrets(r.Context(), namespace)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}
	// Filter before the drift loop: an invisible namespace is not worth a Git fetch.
	if namespace == "" {
		identity, _ := authmw.GetIdentity(r.Context())
		visible := secrets[:0]
		for _, secret := range secrets {
			if containsString(identity.CapabilitiesFor(secret.Namespace), string(policy.MetadataRead)) {
				visible = append(visible, secret)
			}
		}
		secrets = visible
	}
	items := make([]map[string]any, 0, len(secrets))
	// One transport per listing: the shared snapshot keeps this from being a fetch per Secret.
	transport := h.requestTransport()
	started := time.Now()
	result := opResultSuccess
	for i := range secrets {
		git, gitErr := h.gitStatus(r.Context(), transport, secrets[i].Namespace, secrets[i].Name, secrets[i].YAML, "", false, false)
		if gitErr != nil {
			// Degraded, not silent; only the first failure is logged — they share one cause.
			if result != opResultDegraded {
				slog.Warn("listing git status failed",
					"namespace", secrets[i].Namespace, "name", secrets[i].Name,
					"request_id", requestID(r), "error", gitErr)
			}
			result = opResultDegraded
			git = map[string]any{"managed": true, "in_sync_with_live": false, "drift": string(kubernetes.DriftUnknown)}
		}
		items = append(items, map[string]any{
			"name": secrets[i].Name, "namespace": secrets[i].Namespace,
			// Key names travel with the listing; read from spec.encryptedData, never decrypted.
			"keys": secrets[i].Keys, "key_count": secrets[i].KeyCount,
			"scope": secrets[i].Scope, "created_at": secrets[i].CreatedAt, "git": git,
		})
	}
	metrics.RecordSecretListing(result, len(items), time.Since(started))
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
	// namespace/name populate only after the decode, so earlier refusals record an event with nothing named.
	var namespace, name string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "seal", namespace, name, "", "", result) }()

	if !hasCapabilityAnywhere(w, r, policy.SecretSeal) {
		result = opResultDenied
		return
	}
	if h.Crypto == nil {
		result = opResultDisabled
		writeError(w, r, http.StatusServiceUnavailable, "CRYPTO_UNAVAILABLE", "Crypto unavailable")
		return
	}
	var req encryptRequest
	if !decodeJSONBody(w, r, &req) {
		result = opResultInvalidRequest
		return
	}
	if req.Namespace == "" || req.Name == "" || req.YAML == "" || !validName(req.Namespace) || !validName(req.Name) {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	// Past validation the request names a resource, so the audit record can too.
	namespace, name = req.Namespace, req.Name

	// The real namespace question, now that the body has named and validated the target.
	if !requireCapability(w, r, req.Namespace, policy.SecretSeal) {
		result = opResultDenied
		return
	}

	// Refuse a non-Secret before it reaches policy resolution or Git.
	normalized, err := normalizeSecretYAML(req.YAML, req.Namespace, req.Name)
	if err != nil {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Manifest is not a Kubernetes Secret for this name and namespace")
		return
	}
	req.YAML = normalized

	// Resolved once so the vacancy gate and the response's base_commit use the same path.
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
	// Cluster-wide widens the blast radius, so it also requires access:manage.
	if scope == crypto.ClusterWideScope && !requireCapability(w, r, policy.AnyNamespace, policy.AccessManage) {
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
	// The path the vacancy gate read; echoing it keeps a create from being delivered to an unchecked default.
	jsonResponse(w, http.StatusOK, map[string]string{"yaml": sealed, "base_commit": baseCommit, "target_path": mappedPath})
	result = opResultSuccess
}

// resolveEncryptTarget decides which mapped file a new Secret would occupy; mapped=false when there is none, and encrypt keeps working unmapped.
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
		// A 400 for the client, but the audit outcome is a denial, not invalid_request.
		*result = opResultDenied
		writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
		return policy.GitMapping{}, false, "", false
	}
	// No transport skips the vacancy gate; `mapped` is what authorizes that call.
	if h.GitTransport == nil {
		return policy.GitMapping{}, false, "", true
	}
	return mapping, true, req.TargetPath, true
}

// encryptTargetIsVacant enforces the vacant-target gate; a vacant path still returns the branch head for BaseCommit.
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
	// Populated once the body is parsed, so a decoded attempt records the key.
	var key string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "reveal", namespace, name, key, "", result) }()

	if !requireCapability(w, r, namespace, policy.SecretDecrypt) {
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
		BaseCommit string `json:"base_commit"`
	}
	if !decodeJSONBody(w, r, &req) {
		result = opResultInvalidRequest
		return
	}
	if strings.TrimSpace(req.Key) == "" || strings.TrimSpace(req.BaseCommit) == "" {
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
	// A cluster-wide value is readable in every namespace, so editing one widens the blast radius
	// the same way creating one does.
	if secret.Scope == "cluster-wide" && !requireCapability(w, r, policy.AnyNamespace, policy.AccessManage) {
		result = opResultDenied
		return
	}
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, req.BaseCommit, false, false)
	if gitErr != nil {
		result = refuseGitRead(w, r, gitErr)
		return
	}
	if git["drift"] != string(kubernetes.DriftSync) {
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
	value, ok := extractStringDataKey(plain, key)
	if !ok {
		result = opResultNotFound
		writeError(w, r, http.StatusNotFound, "KEY_NOT_FOUND", "Key not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]string{"key": key, "value": value})
	result = opResultSuccess
}

// maxBatchKeys matches the documented 400-key Secret maximum, so any accepted Secret reseals in one batch.
const maxBatchKeys = 400

// mutationRequest is one entry change on the wire, shared by the diff and patch endpoints so they cannot accept different shapes.
type mutationRequest struct {
	Key       string `json:"key"`
	Operation string `json:"operation"`
	Value     string `json:"value"`
}

// parseMutations does shape checks only; key-existence checks are the crypto layer's, as ErrInvalidMutation.
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

// mutationSummary echoes keys and operations, never values.
func mutationSummary(mutations []mutationRequest) []map[string]string {
	out := make([]map[string]string, 0, len(mutations))
	for _, m := range mutations {
		out = append(out, map[string]string{"key": strings.TrimSpace(m.Key), "operation": m.Operation})
	}
	return out
}

// DiffHandler computes an encrypted before/after diff for a batch of key changes without persisting anything.
func (h *ProtectedHandlers) DiffHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	// Diff seals only the values it introduces, but it still names every key the batch touches, so
	// it is audited like patch and reveal.
	var changedKeys string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "diff", namespace, name, changedKeys, "", result) }()

	if !requireCapability(w, r, namespace, policy.SecretSeal) {
		result = opResultDenied
		return
	}
	if h.Crypto == nil {
		result = opResultDisabled
		writeError(w, r, http.StatusServiceUnavailable, "CRYPTO_UNAVAILABLE", "Crypto unavailable")
		return
	}
	var req struct {
		Mutations  []mutationRequest `json:"mutations"`
		BaseCommit string            `json:"base_commit"`
	}
	if !decodeJSONBody(w, r, &req) {
		result = opResultInvalidRequest
		return
	}
	if strings.TrimSpace(req.BaseCommit) == "" {
		result = opResultInvalidRequest
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	// Refusable-without-decrypt checks come before the idempotency key is spent.
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
	// A cluster-wide value is readable in every namespace, so editing one widens the blast radius
	// the same way creating one does.
	if secret.Scope == "cluster-wide" && !requireCapability(w, r, policy.AnyNamespace, policy.AccessManage) {
		result = opResultDenied
		return
	}
	transport := h.requestTransport()
	git, gitErr := h.gitStatus(r.Context(), transport, namespace, name, secret.YAML, req.BaseCommit, false, false)
	if gitErr != nil {
		result = refuseGitRead(w, r, gitErr)
		return
	}
	if git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	// The file discovery actually found; refused when absent, since an empty target_path would fall back to the template.
	targetPath, ok := git["file_path"].(string)
	if !ok || targetPath == "" {
		result = opResultFailed
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	// "Git, before" is the file as Git holds it, read from the snapshot gitStatus already pulled.
	before, readErr := h.mappedFileText(r.Context(), transport, namespace, targetPath)
	if readErr != nil {
		result = opResultFailed
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	after, err := h.Crypto.SealMutations(r.Context(), secret.YAML, mutations)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidMutation) {
			result = opResultInvalidRequest
			writeError(w, r, http.StatusBadRequest, "INVALID_MUTATION", "Invalid mutation")
			return
		}
		result = opResultFailed
		slog.Error("seal secret failed", "namespace", namespace, "name", name, "keys", changedKeys, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to apply changes")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonResponse(w, http.StatusOK, map[string]any{"before": before, "after": after, "mutations": mutationSummary(req.Mutations), "base_commit": req.BaseCommit, "checksum": encryptedChecksum(after), "target_path": targetPath})
	result = opResultSuccess
}

// ResealHandler applies the batch without decrypting, then re-validates against the live Secret at confirm time.
func (h *ProtectedHandlers) ResealHandler(w http.ResponseWriter, r *http.Request) {
	namespace, name := chi.URLParam(r, "namespace"), chi.URLParam(r, "name")
	// Populated once the body is parsed, so the audit record names every key the patch touched.
	var changedKeys string
	result := opResultFailed
	defer func() { h.emitSecurityEvent(r, "patch", namespace, name, changedKeys, "", result) }()

	if !requireCapability(w, r, namespace, policy.SecretSeal) {
		result = opResultDenied
		return
	}
	if h.Crypto == nil {
		result = opResultDisabled
		writeError(w, r, http.StatusServiceUnavailable, "CRYPTO_UNAVAILABLE", "Crypto unavailable")
		return
	}
	var req struct {
		Mutations  []mutationRequest `json:"mutations"`
		BaseCommit string            `json:"base_commit"`
	}
	if !decodeJSONBody(w, r, &req) {
		result = opResultInvalidRequest
		return
	}
	if strings.TrimSpace(req.BaseCommit) == "" {
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
	// A cluster-wide value is readable in every namespace, so editing one widens the blast radius
	// the same way creating one does.
	if secret.Scope == "cluster-wide" && !requireCapability(w, r, policy.AnyNamespace, policy.AccessManage) {
		result = opResultDenied
		return
	}
	git, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, secret.YAML, req.BaseCommit, false, false)
	if gitErr != nil {
		result = refuseGitRead(w, r, gitErr)
		return
	}
	if git["drift"] != string(kubernetes.DriftSync) {
		result = opResultConflict
		writeError(w, r, http.StatusConflict, "GIT_DRIFT", "Git and live secret differ")
		return
	}
	sealed, err := h.Crypto.SealMutations(r.Context(), secret.YAML, mutations)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidMutation) {
			result = opResultInvalidRequest
			writeError(w, r, http.StatusBadRequest, "INVALID_MUTATION", "Invalid mutation")
			return
		}
		result = opResultFailed
		slog.Error("seal secret failed", "namespace", namespace, "name", name, "keys", changedKeys, "request_id", requestID(r), "error", err)
		writeError(w, r, http.StatusBadGateway, "RESEAL_FAILED", "Unable to apply changes")
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
