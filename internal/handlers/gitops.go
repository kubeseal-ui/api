package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/metrics"
	"github.com/kubeseal-ui/api/internal/policy"
)

// gitChangeRequest is the validated input shared by the GitOps dry-run and delivery endpoints. It
// carries the namespace and name alongside the change because the proposal branch is derived from
// the secret's identity (namespace/name), not from the repository or file path.
type gitChangeRequest struct {
	Change    gitops.Change
	Mapping   policy.GitMapping
	Namespace string
	Name      string
	// RequestedPath is the target_path the client sent, empty when it named no file. It is kept
	// alongside Change.Target.Path because the two differ until resolveDeliveryPath settles it.
	RequestedPath string
}

// errManifestNotSealedSecret marks a payload that is not the SealedSecret the request names. It is
// separate from the generic invalid-request error so both GitOps handlers can say what was wrong
// with the manifest rather than only that something was.
var errManifestNotSealedSecret = errors.New("manifest is not a SealedSecret for this name and namespace")

// validateManifest reports whether the reviewed ciphertext is a SealedSecret for the name and
// namespace this request names.
//
// The payload is committed exactly as it arrives, and nothing earlier establishes that it is a
// manifest: a client posting back an encoded form of the ciphertext — base64, say — satisfies every
// other check and commits a file the sealed-secrets controller cannot read, a failure that surfaces
// only later as an app that will not reconcile. Checked after the capability check, so an
// unauthorized caller is refused for that reason and learns nothing about the payload.
func (cr gitChangeRequest) validateManifest() error {
	if !gitops.MatchesSealedSecret(cr.Change.Content, cr.Namespace, cr.Name) {
		return errManifestNotSealedSecret
	}
	return nil
}

func (h *ProtectedHandlers) gitChange(r *http.Request) (gitChangeRequest, error) {
	var req struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		YAML       string `json:"yaml"`
		BaseCommit string `json:"base_commit"`
		TargetPath string `json:"target_path,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validName(req.Namespace) || !validName(req.Name) || req.YAML == "" || req.BaseCommit == "" {
		return gitChangeRequest{}, errors.New("invalid request")
	}
	if h.GitMappings == nil || h.GitTransport == nil {
		return gitChangeRequest{}, errors.New("gitops unavailable")
	}
	mapping, ok := h.GitMappings.GetGitMapping(req.Namespace)
	if !ok {
		return gitChangeRequest{}, errors.New("mapping not found")
	}

	// The path is *not* settled here. Whether a client-named file is usable depends on the
	// mapping and on where this identity's manifest actually lives, and answering that needs a
	// repository read — which belongs after the capability check, not in a parser before it.
	path := req.TargetPath
	if path == "" {
		path = mapping.RenderPath(req.Namespace, req.Name)
	}
	if path == "" {
		return gitChangeRequest{}, errors.New("invalid mapping")
	}
	return gitChangeRequest{
		Change:        gitops.Change{Target: gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path}, BaseCommit: req.BaseCommit, Content: []byte(req.YAML)},
		Mapping:       mapping,
		Namespace:     req.Namespace,
		Name:          req.Name,
		RequestedPath: req.TargetPath,
	}, nil
}

// errTargetPathNotAllowed marks a delivery destination the mapping does not permit: a named path
// that is not where this identity's manifest lives, or — for a manifest that has no file yet — a
// path outside the ones the mapping allows.
var errTargetPathNotAllowed = errors.New("target path not allowed by namespace mapping")

// resolveDeliveryPath settles which file a change is written to, and returns the change with its
// target path filled in. It runs after the capability check, since the read it performs must not
// be reachable by a caller who cannot deliver into the namespace.
func (h *ProtectedHandlers) resolveDeliveryPath(ctx context.Context, cr gitChangeRequest) (gitops.Change, error) {
	change := cr.Change
	path, err := h.resolveDestination(ctx, h.requestTransport(), cr.Mapping, cr.Namespace, cr.Name, cr.RequestedPath)
	if err != nil {
		return change, err
	}
	if path == "" {
		return change, errTargetPathNotAllowed
	}
	change.Target.Path = path
	return change, nil
}

// resolveDestination returns the file a delivery for this SealedSecret writes to, or
// errTargetPathNotAllowed when the mapping permits none. An empty path with a nil error means the
// mapping renders no path and the caller named none either.
//
// It answers where this SealedSecret already lives, because that is the only file a delivery may
// write: the mapping's pathTemplate is a default, not a location, and a Secret kept in an
// application subdirectory is found by the tree walk somewhere the template does not render.
// Writing the templated path would create a second file claiming the same identity while the
// application keeps reading the stale ciphertext.
//
// So a caller may not choose among the files the mapping allows: once this identity has a file, any
// other named path is refused, even one the allowlist admits — the allowlist grants destinations for
// manifests that do not exist yet, not a licence to write an existing one twice. Both write paths
// resolve through here, so the rule a delivery obeys and the rule a sync obeys cannot drift apart.
func (h *ProtectedHandlers) resolveDestination(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, namespace, name, requested string) (string, error) {
	defaultPath := mapping.RenderPath(namespace, name)
	if defaultPath == "" {
		// No template for this identity: nowhere to discover, and — since IsPathAllowed refuses
		// every path when the render is empty — nowhere the caller may name either.
		if requested == "" {
			return "", nil
		}
		return "", errTargetPathNotAllowed
	}
	existing, found, err := h.findManifestFor(ctx, transport, mapping, gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: defaultPath}, namespace, name)
	if err != nil {
		// A read that failed has said nothing about where the manifest is, and the caller must
		// not read that as a vacancy: writing on a failed look is how a duplicate gets created.
		return "", err
	}
	if found {
		if requested != "" && requested != existing {
			// A named path this identity has no manifest at is a request to write somewhere the
			// reviewed content does not belong — refused rather than quietly redirected, which
			// would deliver a change to a file the operator never reviewed.
			return "", errTargetPathNotAllowed
		}
		return existing, nil
	}
	// No file for this identity yet, so the mapping decides where it may go. Its own rendered
	// template is always accepted — refusing it would mean the path /secrets/encrypt echoes back
	// for a create is one the delivery endpoints then reject — and the allowlist adds the
	// alternatives a caller may name instead.
	if requested != "" {
		if requested != defaultPath && !mapping.IsPathAllowed(requested, namespace, name) {
			return "", errTargetPathNotAllowed
		}
		return requested, nil
	}
	return defaultPath, nil
}

// findManifestFor returns the path of this identity's manifest, and whether the repository holds
// one at all.
//
// Two-tier discovery, and unlike the read path a file at the templated path counts only when it
// *is* this identity's manifest: a repository keeping several Secrets in one file, or whose template
// does not encode the name, has a manifest there belonging to someone else, and treating it as this
// identity's would write one Secret over another's. Tier 2 matches on the manifest's own metadata.
func (h *ProtectedHandlers) findManifestFor(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, target gitops.Target, namespace, name string) (string, bool, error) {
	snapshot, err := transport.ReadManifest(ctx, target, mapping.AuthRef)
	if err == nil {
		if gitops.MatchesSealedSecret(snapshot.Content, namespace, name) {
			return target.Path, true, nil
		}
	} else if !errors.Is(err, gitops.ErrNotFound) {
		return "", false, err
	}
	found, searchErr := transport.SearchManifest(ctx, mapping.Repository, mapping.Branch, namespace, name, mapping.AuthRef)
	if searchErr != nil {
		if errors.Is(searchErr, gitops.ErrNotFound) {
			return "", false, nil
		}
		return "", false, searchErr
	}
	if found.Target.Path == "" {
		return "", false, nil
	}
	return found.Target.Path, true, nil
}

// proposalBranch derives the server-side proposal branch for a change. Clients never choose the
// branch; the name is deterministic from the namespace and secret so a retried delivery reconciles
// onto the same branch rather than creating duplicates.
func proposalBranch(namespace, name string) string {
	return "kubeseal-ui/" + namespace + "-" + name
}

func (h *ProtectedHandlers) GitOpsDryRunHandler(w http.ResponseWriter, r *http.Request) {
	cr, err := h.gitChange(r)
	if err != nil {
		h.emitSecurityEvent(r, "gitops_dry_run", "", "", "", "", "failed")
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	change, mapping := cr.Change, cr.Mapping
	if !hasGitCapability(r, mapping.Namespace, mapping.Mode) {
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	if err = cr.validateManifest(); err != nil {
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_manifest")
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Manifest is not a SealedSecret for this name and namespace")
		return
	}
	// The dry run previews the file the delivery will then write, so both resolve the path the
	// same way; a preview of a different file would describe a change that is not the one delivered.
	resolved, err := h.resolveDeliveryPath(r.Context(), cr)
	if err != nil {
		if errors.Is(err, errTargetPathNotAllowed) {
			h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_target_path")
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "error")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	change = resolved
	diff, err := h.GitTransport.DryRun(r.Context(), change, mapping.AuthRef)
	if err != nil {
		var base *gitops.BaseCommitError
		if errors.As(err, &base) {
			h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "conflict")
			writeError(w, r, http.StatusConflict, "BASE_COMMIT_CONFLICT", "Base commit conflict")
			return
		}
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "error")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "success")
	// "after" is the key the client reads and posts straight back to /gitops/deliver; "diff" stays
	// for compatibility with the original handler response.
	jsonResponse(w, http.StatusOK, gitOpsDryRunResponse{
		Before:     string(diff.Before),
		After:      string(diff.After),
		Diff:       string(diff.After),
		Path:       change.Target.Path,
		BaseCommit: change.BaseCommit,
		Mode:       mapping.Mode,
	})
}

// gitOpsDryRunResponse is the dry-run wire contract. The manifest fields are strings because
// encoding/json renders a []byte as base64: the client keeps `after` and posts it straight back to
// /gitops/deliver, so returning the byte slice committed a file that parses as neither YAML nor
// JSON — a bug produced by two endpoints that each look correct alone.
type gitOpsDryRunResponse struct {
	Before     string                 `json:"before"`
	After      string                 `json:"after"`
	Diff       string                 `json:"diff"`
	Path       string                 `json:"path"`
	BaseCommit string                 `json:"base_commit"`
	Mode       policy.GitDeliveryMode `json:"mode"`
}

// gitDeliveryLog records the Git-side detail the security event does not carry. That event's
// namespace and resource fields name the Secret, which is what the audit trail is queried by, so
// the repository and file path belong beside it here rather than in those fields.
func gitDeliveryLog(r *http.Request, cr gitChangeRequest, change gitops.Change, branch, result string, err error) {
	attrs := []any{
		"namespace", cr.Namespace, "name", cr.Name,
		"repository", change.Target.Repository, "branch", branch, "path", change.Target.Path,
		"result", result, "request_id", requestID(r),
	}
	if err != nil {
		attrs = append(attrs, "error", err)
	}
	slog.Info("gitops delivery", attrs...)
}

func (h *ProtectedHandlers) GitOpsDeliverHandler(w http.ResponseWriter, r *http.Request) {
	cr, err := h.gitChange(r)
	if err != nil {
		h.emitSecurityEvent(r, "gitops_delivery", "", "", "", "", "failed")
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	change, mapping := cr.Change, cr.Mapping
	if !hasGitCapability(r, mapping.Namespace, mapping.Mode) {
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "denied")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	// Checked before the idempotency store is consulted: a payload that cannot be delivered is not
	// an attempt whose result is worth recording.
	if err = cr.validateManifest(); err != nil {
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_manifest")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "invalid_manifest")
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Manifest is not a SealedSecret for this name and namespace")
		return
	}
	if mapping.Mode == policy.GitDeliveryProposal && mapping.ProposalAdapter == nil {
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "proposal_unavailable")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "proposal_unavailable")
		writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
		return
	}
	// Resolved here rather than in gitChange so the repository read it may perform happens after
	// the capability check and before the idempotency store is consulted: a path this namespace has
	// no manifest for is a refusal, not an attempt whose result is worth recording.
	resolved, err := h.resolveDeliveryPath(r.Context(), cr)
	if err != nil {
		if errors.Is(err, errTargetPathNotAllowed) {
			h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_target_path")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "invalid_target_path")
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "error")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "failed")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	change = resolved
	// A retry of a delivery that already succeeded is answered with its original response rather
	// than refused — see beginDelivery.
	w, finishDelivery, proceed := h.beginDelivery(w, r)
	if !proceed {
		return
	}
	defer finishDelivery()
	// The branch is derived from the secret's identity (namespace/name) so a retry — or the same
	// change delivered through the sync endpoint — reconciles onto one branch, and a proposal
	// namespace never pushes the mapped direct branch.
	if mapping.Mode == policy.GitDeliveryProposal {
		change.Branch = proposalBranch(cr.Namespace, cr.Name)
	}
	// The branch this push lands on, resolved the way the transport resolves it, for log lines
	// written before a PushResult exists.
	branch := change.Branch
	if branch == "" {
		branch = change.Target.Branch
	}
	pushed, err := h.GitTransport.PushBranch(r.Context(), change, mapping.AuthRef)
	if err != nil {
		var conflict *gitops.ConflictError
		if errors.As(err, &conflict) {
			gitDeliveryLog(r, cr, change, branch, "conflict", err)
			h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "conflict")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "conflict")
			writeError(w, r, http.StatusConflict, "GIT_CONFLICT", "Git conflict")
			return
		}
		gitDeliveryLog(r, cr, change, branch, "failed", err)
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "error")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "failed")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	result := map[string]any{"mode": mapping.Mode, "commit_sha": pushed.Commit, "branch": pushed.Branch, "file_path": change.Target.Path, "argocd_sync_verified": false}
	if mapping.Mode == policy.GitDeliveryProposal {
		provider := mapping.ProposalAdapter
		if provider == nil {
			gitDeliveryLog(r, cr, change, pushed.Branch, "proposal_unavailable", nil)
			h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "proposal_unavailable")
			writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
			return
		}
		proposal, err := provider.OpenProposal(r.Context(), gitops.ProposalRequest{Change: change, Push: pushed})
		if err != nil {
			gitDeliveryLog(r, cr, change, pushed.Branch, "proposal_failed", err)
			h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "proposal_failed")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "proposal_failed")
			writeError(w, r, http.StatusBadGateway, "PROPOSAL_FAILED", "Proposal failed")
			return
		}
		result["proposal_url"] = proposal.URL
	}
	gitDeliveryLog(r, cr, change, pushed.Branch, "success", nil)
	h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "success")
	metrics.RecordGitOpsDelivery(string(mapping.Mode), "success")
	jsonResponse(w, http.StatusOK, result)
}

// hasGitCapability reports whether the caller may deliver into the namespace the mapping resolved
// to: delivering into a namespace is an act in that namespace, so a grant scoped elsewhere does
// not carry the capability here.
func hasGitCapability(r *http.Request, namespace string, mode policy.GitDeliveryMode) bool {
	id, _ := authmw.GetIdentity(r.Context())
	return id.HasCapabilityIn(namespace, string(policy.GitOpsCapabilityRequired(mode)))
}

// GitOpsSyncStatusHandler returns the drift status between the live cluster and Git, locating the
// manifest via two-tier source discovery (fast-path pathTemplate, then a Git tree walk).
func (h *ProtectedHandlers) GitOpsSyncStatusHandler(w http.ResponseWriter, r *http.Request) {
	// The namespace is a query parameter here, so it is read before the check is about it.
	namespace := r.URL.Query().Get("namespace")
	name := r.URL.Query().Get("name")
	if !requireCapability(w, r, namespace, policy.MetadataRead) {
		return
	}
	if !validName(namespace) || !validName(name) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid namespace or name")
		return
	}
	if h.GitMappings == nil || h.GitTransport == nil {
		writeError(w, r, http.StatusServiceUnavailable, "GITOPS_UNAVAILABLE", "GitOps not configured")
		return
	}
	_, ok := h.GitMappings.GetGitMapping(namespace)
	if !ok {
		writeError(w, r, http.StatusNotFound, "MAPPING_NOT_FOUND", "No Git mapping for namespace")
		return
	}

	var liveExists bool
	var liveYAML string
	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), namespace, name)
	if err != nil {
		if !errors.Is(err, kubernetes.ErrNotFound) {
			writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
			return
		}
	} else {
		liveExists = true
		liveYAML = secret.YAML
	}

	gitStat, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, liveYAML, "", true)
	if gitErr != nil {
		writeError(w, r, http.StatusConflict, "GIT_STATE_UNAVAILABLE", "Git source unavailable")
		return
	}

	driftVal, ok := gitStat["drift"].(string)
	if !ok || driftVal == "" {
		driftVal = "unknown"
	}
	gitExists := driftVal != "live_only" && gitStat["managed"] == true

	result := map[string]any{
		"namespace":     namespace,
		"name":          name,
		"managed":       gitStat["managed"],
		"file_path":     gitStat["file_path"],
		"repository":    gitStat["repository"],
		"branch":        gitStat["branch"],
		"delivery_mode": gitStat["delivery_mode"],
		"base_commit":   gitStat["base_commit"],
		"drift_status":  driftVal,
		"can_sync":      driftVal == "live_only" || driftVal == string(kubernetes.DriftDiverged),
		// Report-only: can_sync stays true, because the sync is refused by nothing on the server —
		// the client withholds it and offers an override. See gitStatus.
		"git_moved_ahead": gitStat["git_moved_ahead"] == true,
		"live": map[string]any{
			"exists": liveExists,
		},
		"git": map[string]any{
			"exists": gitExists,
		},
	}

	jsonResponse(w, http.StatusOK, result)
}

// GitOpsSyncHandler syncs a live SealedSecret from Kubernetes to Git. The client supplies only
// { namespace, name, base_commit }; the server reads the live YAML and pushes it to the configured
// or discovered Git path, using the same two-tier discovery as the status endpoint.
func (h *ProtectedHandlers) GitOpsSyncHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		BaseCommit string `json:"base_commit"`
		TargetPath string `json:"target_path,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		h.emitSecurityEvent(r, "gitops_sync", "", "", "", "", "failed")
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if !validName(req.Namespace) || !validName(req.Name) || req.BaseCommit == "" {
		h.emitSecurityEvent(r, "gitops_sync", "", "", "", "", "failed")
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}

	if h.GitMappings == nil || h.GitTransport == nil {
		writeError(w, r, http.StatusServiceUnavailable, "GITOPS_UNAVAILABLE", "GitOps not configured")
		return
	}
	mapping, ok := h.GitMappings.GetGitMapping(req.Namespace)
	if !ok {
		writeError(w, r, http.StatusNotFound, "MAPPING_NOT_FOUND", "No Git mapping for namespace")
		return
	}
	if !hasGitCapability(r, mapping.Namespace, mapping.Mode) {
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	if mapping.Mode == policy.GitDeliveryProposal && mapping.ProposalAdapter == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
		return
	}
	// A retry of a sync that already succeeded is answered with its original response rather than
	// refused — see beginDelivery.
	w, finishDelivery, proceed := h.beginDelivery(w, r)
	if !proceed {
		return
	}
	defer finishDelivery()

	secret, err := h.Kubernetes.GetSealedSecret(r.Context(), req.Namespace, req.Name)
	if err != nil {
		if errors.Is(err, kubernetes.ErrNotFound) {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "not_found")
			writeError(w, r, http.StatusNotFound, "NOT_FOUND", "Secret not found in cluster")
			return
		}
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "k8s_error")
		writeError(w, r, http.StatusBadGateway, "DEPENDENCY_UNAVAILABLE", "Kubernetes unavailable")
		return
	}

	// The live object was just read by this name and namespace, so it is a SealedSecret by
	// construction. Validated anyway: the same guard the dry-run and delivery endpoints apply is
	// what makes "only a manifest this mapping owns is committed" true of the product.
	if !gitops.MatchesSealedSecret([]byte(secret.YAML), req.Namespace, req.Name) {
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "invalid_manifest")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "invalid_manifest")
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Live object is not a SealedSecret for this name and namespace")
		return
	}

	// The destination is where this identity's manifest already lives, resolved by the same rule a
	// delivery obeys — see resolveDestination.
	path, resolveErr := h.resolveDestination(r.Context(), h.requestTransport(), mapping, req.Namespace, req.Name, req.TargetPath)
	if resolveErr != nil {
		if errors.Is(resolveErr, errTargetPathNotAllowed) {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "invalid_target_path")
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		// A Git that could not be read has not established that the manifest is absent, and syncing
		// on that assumption would create a second file for an identity that already has one.
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "error")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	if path == "" {
		writeError(w, r, http.StatusInternalServerError, "INVALID_MAPPING", "Git path could not be resolved")
		return
	}

	change := gitops.Change{
		Target:     gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path},
		BaseCommit: req.BaseCommit,
		Content:    []byte(secret.YAML),
	}

	// Proposal mode: push to a dedicated branch, then open a PR.
	if mapping.Mode == policy.GitDeliveryProposal {
		change.Branch = proposalBranch(req.Namespace, req.Name)
	}

	pushed, err := h.GitTransport.PushBranch(r.Context(), change, mapping.AuthRef)
	if err != nil {
		var conflict *gitops.ConflictError
		if errors.As(err, &conflict) {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "conflict")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "conflict")
			writeError(w, r, http.StatusConflict, "GIT_CONFLICT", "Git conflict")
			return
		}
		var base *gitops.BaseCommitError
		if errors.As(err, &base) {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "conflict")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "conflict")
			writeError(w, r, http.StatusConflict, "BASE_COMMIT_CONFLICT", "Base commit conflict")
			return
		}
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "error")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "failed")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}

	result := map[string]any{
		"mode":                 mapping.Mode,
		"commit_sha":           pushed.Commit,
		"branch":               pushed.Branch,
		"file_path":            path,
		"namespace":            req.Namespace,
		"name":                 req.Name,
		"argocd_sync_verified": false,
	}

	if mapping.Mode == policy.GitDeliveryProposal {
		provider := mapping.ProposalAdapter
		proposal, err := provider.OpenProposal(r.Context(), gitops.ProposalRequest{Change: change, Push: pushed})
		if err != nil {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "proposal_failed")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "proposal_failed")
			writeError(w, r, http.StatusBadGateway, "PROPOSAL_FAILED", "Proposal failed")
			return
		}
		result["proposal_url"] = proposal.URL
	}

	h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "success")
	metrics.RecordGitOpsDelivery(string(mapping.Mode), "success")
	jsonResponse(w, http.StatusOK, result)
}
