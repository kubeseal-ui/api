package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/metrics"
	"github.com/kubeseal-ui/api/internal/policy"
)

func (h *ProtectedHandlers) gitChange(r *http.Request) (gitops.Change, policy.GitMapping, error) {
	var req struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		YAML       string `json:"yaml"`
		BaseCommit string `json:"base_commit"`
		TargetPath string `json:"target_path,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validName(req.Namespace) || !validName(req.Name) || req.YAML == "" || req.BaseCommit == "" {
		return gitops.Change{}, policy.GitMapping{}, errors.New("invalid request")
	}
	if h.GitMappings == nil || h.GitTransport == nil {
		return gitops.Change{}, policy.GitMapping{}, errors.New("gitops unavailable")
	}
	mapping, ok := h.GitMappings.GetGitMapping(req.Namespace)
	if !ok {
		return gitops.Change{}, policy.GitMapping{}, errors.New("mapping not found")
	}
	
	// If targetPath provided, validate it against the mapping's allowed paths
	var path string
	if req.TargetPath != "" {
		if !mapping.IsPathAllowed(req.TargetPath, req.Namespace, req.Name) {
			return gitops.Change{}, policy.GitMapping{}, errors.New("target path not allowed by namespace mapping")
		}
		path = req.TargetPath
	} else {
		path = mapping.RenderPath(req.Namespace, req.Name)
	}
	if path == "" {
		return gitops.Change{}, policy.GitMapping{}, errors.New("invalid mapping")
	}
	return gitops.Change{Target: gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path}, BaseCommit: req.BaseCommit, Content: []byte(req.YAML)}, mapping, nil
}

// proposalBranch derives the server-side proposal branch for a change.
// Clients never choose the branch; the name is deterministic from the
// namespace and secret so a retried delivery reconciles onto the same
// branch rather than creating duplicates.
func proposalBranch(namespace, name string) string {
	return "kubeseal-ui/" + namespace + "-" + name
}

func (h *ProtectedHandlers) GitOpsDryRunHandler(w http.ResponseWriter, r *http.Request) {
	change, mapping, err := h.gitChange(r)
	if err != nil {
		h.emitSecurityEvent(r, "gitops_dry_run", "", "", "", "", "failed")
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if !hasGitCapability(r, mapping.Mode) {
		h.emitSecurityEvent(r, "gitops_dry_run", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	diff, err := h.GitTransport.DryRun(r.Context(), change, mapping.AuthRef)
	if err != nil {
		var base *gitops.BaseCommitError
		if errors.As(err, &base) {
			h.emitSecurityEvent(r, "gitops_dry_run", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "conflict")
			writeError(w, r, http.StatusConflict, "BASE_COMMIT_CONFLICT", "Base commit conflict")
			return
		}
		h.emitSecurityEvent(r, "gitops_dry_run", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "error")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	h.emitSecurityEvent(r, "gitops_dry_run", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "success")
	// The doc contract calls for "encrypted diff, resolved path, base
	// commit, and fixed delivery mode". The after ciphertext flows under
	// "after" (the key the client reads) and "diff" stays for compatibility
	// with the original handler response.
	jsonResponse(w, http.StatusOK, map[string]any{"after": diff.After, "diff": diff.After, "before": diff.Before, "path": change.Target.Path, "base_commit": change.BaseCommit, "mode": mapping.Mode})
}

func (h *ProtectedHandlers) GitOpsDeliverHandler(w http.ResponseWriter, r *http.Request) {
	change, mapping, err := h.gitChange(r)
	if err != nil {
		h.emitSecurityEvent(r, "gitops_delivery", "", "", "", "", "failed")
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if !hasGitCapability(r, mapping.Mode) {
		h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "denied")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	if mapping.Mode == policy.GitDeliveryProposal && mapping.ProposalAdapter == nil {
		h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "proposal_unavailable")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "proposal_unavailable")
		writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
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
	// Proposal namespaces push a dedicated branch, never the mapped
	// direct branch. Direct namespaces push the mapped branch itself.
	if mapping.Mode == policy.GitDeliveryProposal {
		change.Branch = proposalBranch(change.Target.Repository, change.Target.Path)
	}
	pushed, err := h.GitTransport.PushBranch(r.Context(), change, mapping.AuthRef)
	if err != nil {
		var conflict *gitops.ConflictError
		if errors.As(err, &conflict) {
			h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "conflict")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "conflict")
			writeError(w, r, http.StatusConflict, "GIT_CONFLICT", "Git conflict")
			return
		}
		h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "error")
		metrics.RecordGitOpsDelivery(string(mapping.Mode), "failed")
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	result := map[string]any{"mode": mapping.Mode, "commit_sha": pushed.Commit, "branch": pushed.Branch, "file_path": change.Target.Path, "argocd_sync_verified": false}
	if mapping.Mode == policy.GitDeliveryProposal {
		provider := mapping.ProposalAdapter
		if provider == nil {
			h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "proposal_unavailable")
			writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
			return
		}
		proposal, err := provider.OpenProposal(r.Context(), gitops.ProposalRequest{Change: change, Push: pushed})
		if err != nil {
			h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "proposal_failed")
			metrics.RecordGitOpsDelivery(string(mapping.Mode), "proposal_failed")
			writeError(w, r, http.StatusBadGateway, "PROPOSAL_FAILED", "Proposal failed")
			return
		}
		result["proposal_url"] = proposal.URL
	}
	h.emitSecurityEvent(r, "gitops_delivery", change.Target.Repository, change.Target.Path, "", string(mapping.Mode), "success")
	metrics.RecordGitOpsDelivery(string(mapping.Mode), "success")
	jsonResponse(w, http.StatusOK, result)
}

func hasGitCapability(r *http.Request, mode policy.GitDeliveryMode) bool {
	id, _ := authmw.GetIdentity(r.Context())
	want := policy.GitOpsCapabilityRequired(mode)
	for _, cap := range id.Capabilities {
		if cap == string(want) {
			return true
		}
	}
	return false
}

// GitOpsSyncStatusHandler returns the drift status between live cluster and Git.
// It uses Option A (two-tier source discovery: fast-path pathTemplate with Git tree walk fallback)
// to locate the manifest in Git, and evaluates drift.
func (h *ProtectedHandlers) GitOpsSyncStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !requireCapability(w, r, policy.MetadataRead) {
		return
	}
	namespace := r.URL.Query().Get("namespace")
	name := r.URL.Query().Get("name")
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

	gitStat, gitErr := h.gitStatus(r, namespace, name, liveYAML, "")
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
		"live": map[string]any{
			"exists": liveExists,
		},
		"git": map[string]any{
			"exists": gitExists,
		},
	}

	jsonResponse(w, http.StatusOK, result)
}

// resolveSyncPath resolves the target Git path for a sync using two-tier
// Option A discovery: fast-path template check, then full tree walk fallback.
func (h *ProtectedHandlers) resolveSyncPath(ctx context.Context, mapping policy.GitMapping, namespace, name string) string {
	if defaultPath := mapping.RenderPath(namespace, name); defaultPath != "" {
		_, readErr := h.GitTransport.ReadManifest(ctx, gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: defaultPath}, mapping.AuthRef)
		if readErr == nil {
			return defaultPath
		}
		if errors.Is(readErr, gitops.ErrNotFound) {
			snap, sErr := h.GitTransport.SearchManifest(ctx, mapping.Repository, mapping.Branch, namespace, name, mapping.AuthRef)
			if sErr == nil && snap.Target.Path != "" {
				return snap.Target.Path
			}
		}
		return defaultPath
	}
	return ""
}

// GitOpsSyncHandler syncs a live SealedSecret from Kubernetes to Git.
// The client supplies only { namespace, name, base_commit }; the server
// fetches the live YAML from Kubernetes and pushes it to the configured
// or discovered Git path for that namespace. This resolves drift where the live cluster
// state is ahead of Git (e.g. secrets applied out-of-band).
//
// Matching is done via Option A (Two-Tier Discovery: fast-path pathTemplate with
// Git repository tree walk fallback).
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
	if !hasGitCapability(r, mapping.Mode) {
		h.emitSecurityEvent(r, "gitops_sync", req.Namespace, req.Name, "", string(mapping.Mode), "denied")
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	if mapping.Mode == policy.GitDeliveryProposal && mapping.ProposalAdapter == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
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

	// Fetch the live SealedSecret from Kubernetes.
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

	// Resolve the target path via Two-Tier Discovery.
	var path string
	if req.TargetPath != "" {
		if !mapping.IsPathAllowed(req.TargetPath, req.Namespace, req.Name) {
			writeError(w, r, http.StatusBadRequest, "INVALID_TARGET_PATH", "Target path not allowed by namespace mapping")
			return
		}
		path = req.TargetPath
	} else {
		path = h.resolveSyncPath(r.Context(), mapping, req.Namespace, req.Name)
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
