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

// gitChangeRequest is the validated input shared by the GitOps dry-run and delivery endpoints.
type gitChangeRequest struct {
	Change    gitops.Change
	Mapping   policy.GitMapping
	Namespace string
	Name      string
	// Differs from Change.Target.Path until resolveDeliveryPath settles it.
	RequestedPath string
}

// Distinct from invalid-request so handlers can say what was wrong with the manifest.
var errManifestNotSealedSecret = errors.New("manifest is not a SealedSecret for this name and namespace")

// Payload is committed exactly as it arrives, so it must be this identity's SealedSecret; checked after the capability gate.
func (cr gitChangeRequest) validateManifest() error {
	if !gitops.MatchesSealedSecret(cr.Change.Content, cr.Namespace, cr.Name) {
		return errManifestNotSealedSecret
	}
	return nil
}

// Kept distinct so a handler answers the real cause, not a generic 400.
var (
	errGitChangeInvalidRequest = errors.New("invalid request")
	errGitOpsUnavailable       = errors.New("gitops unavailable")
	errMappingNotFound         = errors.New("mapping not found")
	errInvalidMapping          = errors.New("invalid mapping")
	errRequestBodyTooLarge     = errors.New("request body too large")
)

func (h *ProtectedHandlers) gitChange(w http.ResponseWriter, r *http.Request) (gitChangeRequest, error) {
	var req struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		YAML       string `json:"yaml"`
		BaseCommit string `json:"base_commit"`
		TargetPath string `json:"target_path,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return gitChangeRequest{}, errRequestBodyTooLarge
		}
		return gitChangeRequest{}, errGitChangeInvalidRequest
	}
	if !validName(req.Namespace) || !validName(req.Name) || req.YAML == "" || req.BaseCommit == "" {
		return gitChangeRequest{}, errGitChangeInvalidRequest
	}
	if h.GitMappings == nil || h.GitTransport == nil {
		return gitChangeRequest{}, errGitOpsUnavailable
	}
	mapping, ok := h.GitMappings.GetGitMapping(req.Namespace)
	if !ok {
		return gitChangeRequest{}, errMappingNotFound
	}

	// Settling the path needs a repository read, so it waits for the capability check.
	path := req.TargetPath
	if path == "" {
		path = mapping.RenderPath(req.Namespace, req.Name)
	}
	if path == "" {
		return gitChangeRequest{}, errInvalidMapping
	}
	return gitChangeRequest{
		Change:        gitops.Change{Target: gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path}, BaseCommit: req.BaseCommit, Content: []byte(req.YAML)},
		Mapping:       mapping,
		Namespace:     req.Namespace,
		Name:          req.Name,
		RequestedPath: req.TargetPath,
	}, nil
}

// refuseGitChange answers each failure with the response it actually deserves.
func refuseGitChange(w http.ResponseWriter, r *http.Request, err error) string {
	switch {
	case errors.Is(err, errGitOpsUnavailable):
		writeError(w, r, http.StatusServiceUnavailable, "GITOPS_UNAVAILABLE", "GitOps not configured")
		return "failed"
	case errors.Is(err, errRequestBodyTooLarge):
		writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "Request body too large")
		return "invalid_request"
	case errors.Is(err, errMappingNotFound):
		writeError(w, r, http.StatusNotFound, "MAPPING_NOT_FOUND", "No Git mapping for namespace")
		return "not_found"
	case errors.Is(err, errInvalidMapping):
		writeError(w, r, http.StatusInternalServerError, "INVALID_MAPPING", "Git path could not be resolved")
		return "failed"
	default:
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return "invalid_request"
	}
}

// errTargetPathNotAllowed marks a named path that is not where this identity's manifest lives.
var errTargetPathNotAllowed = errors.New("target path not allowed by namespace mapping")

// errDestinationHeld: the mapping allows the path, but the repository already holds another file there.
var errDestinationHeld = errors.New("destination already holds another manifest")

// resolveDeliveryPath runs after the capability check: the repository read must not be reachable otherwise.
// `existing` is the file's content at the destination, nil when the file is vacant.
func (h *ProtectedHandlers) resolveDeliveryPath(ctx context.Context, cr gitChangeRequest) (gitops.Change, []byte, error) {
	change := cr.Change
	path, existing, err := h.resolveDestination(ctx, h.requestTransport(), cr.Mapping, cr.Namespace, cr.Name, cr.RequestedPath)
	if err != nil {
		return change, nil, err
	}
	if path == "" {
		return change, nil, errTargetPathNotAllowed
	}
	change.Target.Path = path
	return change, existing, nil
}

// mergeIntoExisting splices the incoming manifest into the multi-document file already at the
// destination, so its siblings survive the write; a vacant file takes the content as-is.
func mergeIntoExisting(existing, incoming []byte, namespace, name string) []byte {
	if len(existing) == 0 {
		return incoming
	}
	merged, _ := gitops.SpliceSealedSecret(existing, incoming, namespace, name)
	return merged
}

// resolveDestination returns the file this identity's manifest may be written to, plus the content
// already there (nil when vacant); the allowlist grants destinations for new manifests only.
func (h *ProtectedHandlers) resolveDestination(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, namespace, name, requested string) (string, []byte, error) {
	defaultPath := mapping.RenderPath(namespace, name)
	if defaultPath == "" {
		// No template: nowhere to discover and nowhere the caller may name.
		if requested == "" {
			return "", nil, nil
		}
		return "", nil, errTargetPathNotAllowed
	}
	lookup, err := h.findManifestFor(ctx, transport, mapping, gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: defaultPath}, namespace, name)
	if err != nil {
		// A failed read says nothing about vacancy; writing on one is how a duplicate gets created.
		return "", nil, err
	}
	if lookup.Found {
		if requested != "" && requested != lookup.Path {
			// Refused rather than redirected: reviewed content must not land in an unreviewed file.
			return "", nil, errTargetPathNotAllowed
		}
		return lookup.Path, lookup.Existing, nil
	}
	// The rendered template is always accepted for a create; the allowlist adds the alternatives.
	destination := defaultPath
	if requested != "" {
		if requested != defaultPath && !mapping.IsPathAllowed(requested, namespace, name) {
			return "", nil, errTargetPathNotAllowed
		}
		destination = requested
	}
	if destination == defaultPath {
		// Discovery already read this file, so its verdict is the occupancy answer.
		if lookup.Occupied {
			return "", nil, errDestinationHeld
		}
		return destination, nil, nil
	}
	// The allowlist grants a destination, not the right to replace whatever is already there.
	held, heldErr := h.pathHeldByOther(ctx, transport, mapping, gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: destination}, namespace, name)
	if heldErr != nil {
		return "", nil, heldErr
	}
	if held {
		return "", nil, errDestinationHeld
	}
	return destination, nil, nil
}

// manifestLookup separates Found from Occupied: "not this identity's manifest" is not "vacant".
type manifestLookup struct {
	Path     string
	Found    bool
	Occupied bool
	// The file's content when Found, so the caller can splice into a multi-document file.
	Existing []byte
}

// findManifestFor: two-tier discovery. A file at the templated path counts only when it is this
// identity's manifest; anything else there is reported as Occupied so a create refuses instead of writing over it.
func (h *ProtectedHandlers) findManifestFor(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, target gitops.Target, namespace, name string) (manifestLookup, error) {
	occupied := false
	snapshot, err := transport.ReadManifest(ctx, target, mapping.AuthRef)
	if err == nil {
		if gitops.MatchesSealedSecret(snapshot.Content, namespace, name) {
			return manifestLookup{Path: target.Path, Found: true, Existing: snapshot.Content}, nil
		}
		occupied = true
	} else if !errors.Is(err, gitops.ErrNotFound) {
		return manifestLookup{}, err
	}
	found, searchErr := transport.SearchManifest(ctx, mapping.Repository, mapping.Branch, namespace, name, mapping.AuthRef)
	if searchErr != nil {
		if errors.Is(searchErr, gitops.ErrNotFound) {
			return manifestLookup{Occupied: occupied}, nil
		}
		return manifestLookup{}, searchErr
	}
	if found.Target.Path == "" {
		return manifestLookup{Occupied: occupied}, nil
	}
	return manifestLookup{Path: found.Target.Path, Found: true, Existing: found.Content}, nil
}

// pathHeldByOther: true when target holds another identity's manifest, or not a SealedSecret at all.
func (h *ProtectedHandlers) pathHeldByOther(ctx context.Context, transport gitops.GitTransport, mapping policy.GitMapping, target gitops.Target, namespace, name string) (bool, error) {
	snapshot, err := transport.ReadManifest(ctx, target, mapping.AuthRef)
	if err != nil {
		if errors.Is(err, gitops.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return !gitops.MatchesSealedSecret(snapshot.Content, namespace, name), nil
}

// proposalBranch is deterministic from namespace/name so a retried delivery reconciles onto one branch.
func proposalBranch(namespace, name string) string {
	return "kubeseal-ui/" + namespace + "-" + name
}

func (h *ProtectedHandlers) GitOpsDryRunHandler(w http.ResponseWriter, r *http.Request) {
	cr, err := h.gitChange(w, r)
	if err != nil {
		outcome := refuseGitChange(w, r, err)
		h.emitSecurityEvent(r, "gitops_dry_run", "", "", "", "", outcome)
		return
	}
	mapping := cr.Mapping
	if required, ok := hasGitCapability(r, mapping.Namespace, mapping.Mode); !ok {
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", capabilityDeniedMessage(required))
		return
	}
	if err = cr.validateManifest(); err != nil {
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_manifest")
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Manifest is not a SealedSecret for this name and namespace")
		return
	}
	// Both endpoints resolve the path the same way, or the preview describes a change that is not delivered.
	resolved, existing, err := h.resolveDeliveryPath(r.Context(), cr)
	if err != nil {
		if errors.Is(err, errTargetPathNotAllowed) {
			h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_target_path")
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		if errors.Is(err, errDestinationHeld) {
			h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "path_occupied")
			writeError(w, r, http.StatusConflict, "PATH_OCCUPIED", "Another manifest is already committed at this path")
			return
		}
		h.emitSecurityEvent(r, "gitops_dry_run", cr.Namespace, cr.Name, "", string(mapping.Mode), "error")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	change := resolved
	change.Content = mergeIntoExisting(existing, change.Content, cr.Namespace, cr.Name)
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
	// "after" is what the client posts back to /gitops/deliver; "diff" stays for compatibility.
	jsonResponse(w, http.StatusOK, gitOpsDryRunResponse{
		Before:     string(diff.Before),
		After:      string(diff.After),
		Diff:       string(diff.After),
		Path:       change.Target.Path,
		BaseCommit: change.BaseCommit,
		Mode:       mapping.Mode,
	})
}

// gitOpsDryRunResponse: strings, not []byte — json renders bytes as base64, which once committed a file that parsed as neither YAML nor JSON.
type gitOpsDryRunResponse struct {
	Before     string                 `json:"before"`
	After      string                 `json:"after"`
	Diff       string                 `json:"diff"`
	Path       string                 `json:"path"`
	BaseCommit string                 `json:"base_commit"`
	Mode       policy.GitDeliveryMode `json:"mode"`
}

// gitDeliveryLog records the Git-side detail the security event does not carry.
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
	cr, err := h.gitChange(w, r)
	if err != nil {
		outcome := refuseGitChange(w, r, err)
		h.emitSecurityEvent(r, "gitops_delivery", "", "", "", "", outcome)
		return
	}
	change, mapping := cr.Change, cr.Mapping
	if required, ok := hasGitCapability(r, mapping.Namespace, mapping.Mode); !ok {
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "denied")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", capabilityDeniedMessage(required))
		return
	}
	// Before the idempotency store: an undeliverable payload is not an attempt worth recording.
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
	// Repository read sits after the capability check and before the idempotency store.
	resolved, existing, err := h.resolveDeliveryPath(r.Context(), cr)
	if err != nil {
		if errors.Is(err, errTargetPathNotAllowed) {
			h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "invalid_target_path")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "invalid_target_path")
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		if errors.Is(err, errDestinationHeld) {
			h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "path_occupied")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "path_occupied")
			writeError(w, r, http.StatusConflict, "PATH_OCCUPIED", "Another manifest is already committed at this path")
			return
		}
		h.emitSecurityEvent(r, "gitops_delivery", cr.Namespace, cr.Name, "", string(mapping.Mode), "error")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "failed")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	change = resolved
	change.Content = mergeIntoExisting(existing, change.Content, cr.Namespace, cr.Name)
	// A retry is answered with its original response — see beginDelivery.
	w, finishDelivery, proceed := h.beginDelivery(w, r)
	if !proceed {
		return
	}
	defer finishDelivery()
	// Derived from the identity so retries reconcile onto one branch, never the mapped direct branch.
	if mapping.Mode == policy.GitDeliveryProposal {
		change.Branch = proposalBranch(cr.Namespace, cr.Name)
	}
	// Resolved the way the transport resolves it, for logs written before a PushResult exists.
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
		proposal, err := mapping.ProposalAdapter.OpenProposal(r.Context(), gitops.ProposalRequest{Change: change, Push: pushed})
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

// hasGitCapability: delivery is an act in the mapped namespace, so a grant scoped elsewhere does not carry.
func hasGitCapability(r *http.Request, namespace string, mode policy.GitDeliveryMode) (policy.Capability, bool) {
	id, _ := authmw.GetIdentity(r.Context())
	required := policy.GitOpsCapabilityRequired(mode)
	return required, id.HasCapabilityIn(namespace, string(required))
}

// GitOpsSyncStatusHandler returns drift status between the live cluster and Git, via two-tier manifest discovery.
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

	gitStat, gitErr := h.gitStatus(r.Context(), h.requestTransport(), namespace, name, liveYAML, "", true, true)
	if gitErr != nil {
		writeError(w, r, http.StatusConflict, "GIT_STATE_UNAVAILABLE", "Git source unavailable")
		return
	}

	driftVal, ok := gitStat["drift"].(string)
	if !ok || driftVal == "" {
		driftVal = "unknown"
	}
	gitExists := driftVal != "live_only" && gitStat["managed"] == true
	// Identity drift cannot be synced — the file is another Secret's — so the action is not advertised.
	syncable := (driftVal == "live_only" || driftVal == string(kubernetes.DriftDiverged)) &&
		gitStat["drift_reason"] != driftReasonIdentity

	result := map[string]any{
		"namespace":       namespace,
		"name":            name,
		"managed":         gitStat["managed"],
		"file_path":       gitStat["file_path"],
		"repository":      gitStat["repository"],
		"branch":          gitStat["branch"],
		"delivery_mode":   gitStat["delivery_mode"],
		"base_commit":     gitStat["base_commit"],
		"drift_status":    driftVal,
		"can_sync":        syncable,
		"git_moved_ahead": gitStat["git_moved_ahead"] == true,
		// The file as Git holds it now, so the client can show what a sync replaces.
		"git_file_yaml": gitStat["git_file_yaml"],
		"live": map[string]any{
			"exists": liveExists,
		},
		"git": map[string]any{
			"exists": gitExists,
		},
	}

	jsonResponse(w, http.StatusOK, result)
}

// GitOpsSyncHandler pushes the live SealedSecret to Git; the client supplies only namespace, name, and base_commit.
func (h *ProtectedHandlers) GitOpsSyncHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		BaseCommit string `json:"base_commit"`
		TargetPath string `json:"target_path,omitempty"`
	}
	if !decodeJSONBody(w, r, &req) {
		h.emitSecurityEvent(r, "gitops_sync", "", "", "", "", "failed")
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
	if required, ok := hasGitCapability(r, mapping.Namespace, mapping.Mode); !ok {
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", capabilityDeniedMessage(required))
		return
	}
	if mapping.Mode == policy.GitDeliveryProposal && mapping.ProposalAdapter == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
		return
	}
	// A retry is answered with its original response — see beginDelivery.
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

	// The live object is a SealedSecret by construction; validated with the same guard as delivery.
	if !gitops.MatchesSealedSecret([]byte(secret.YAML), req.Namespace, req.Name) {
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "invalid_manifest")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "invalid_manifest")
		writeError(w, r, http.StatusBadRequest, "INVALID_MANIFEST", "Live object is not a SealedSecret for this name and namespace")
		return
	}

	// Resolved by the same rule a delivery obeys — see resolveDestination.
	path, existing, resolveErr := h.resolveDestination(r.Context(), h.requestTransport(), mapping, req.Namespace, req.Name, req.TargetPath)
	if resolveErr != nil {
		if errors.Is(resolveErr, errTargetPathNotAllowed) {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "invalid_target_path")
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		// A push here would replace that Secret's sealed data and report success.
		if errors.Is(resolveErr, errDestinationHeld) {
			h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "path_occupied")
			writeError(w, r, http.StatusConflict, "PATH_OCCUPIED", "Another manifest is already committed at this path")
			return
		}
		// An unreadable Git has not established absence; syncing would create a second file.
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
		Content:    mergeIntoExisting(existing, []byte(secret.YAML), req.Namespace, req.Name),
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
		proposal, err := mapping.ProposalAdapter.OpenProposal(r.Context(), gitops.ProposalRequest{Change: change, Push: pushed})
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
