package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/policy"
)

func (h *ProtectedHandlers) gitChange(r *http.Request) (gitops.Change, policy.GitMapping, error) {
	var req struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		YAML       string `json:"yaml"`
		BaseCommit string `json:"base_commit"`
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
	path := mapping.RenderPath(req.Namespace, req.Name)
	if path == "" {
		return gitops.Change{}, policy.GitMapping{}, errors.New("invalid mapping")
	}
	return gitops.Change{Target: gitops.Target{Repository: mapping.Repository, Branch: mapping.Branch, Path: path}, BaseCommit: req.BaseCommit, Content: []byte(req.YAML)}, mapping, nil
}

func (h *ProtectedHandlers) GitOpsDryRunHandler(w http.ResponseWriter, r *http.Request) {
	defer h.emitSecurityEvent(r, "gitops_dry_run", "", "", "", "", "attempt")
	change, mapping, err := h.gitChange(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if !hasGitCapability(r, mapping.Mode) {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	diff, err := h.GitTransport.DryRun(r.Context(), change)
	if err != nil {
		var base *gitops.BaseCommitError
		if errors.As(err, &base) {
			writeError(w, r, http.StatusConflict, "BASE_COMMIT_CONFLICT", "Base commit conflict")
			return
		}
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]any{"diff": diff.After, "before": diff.Before, "path": change.Target.Path, "base_commit": change.BaseCommit, "mode": mapping.Mode})
}

func (h *ProtectedHandlers) GitOpsDeliverHandler(w http.ResponseWriter, r *http.Request) {
	defer h.emitSecurityEvent(r, "gitops_delivery", "", "", "", "", "attempt")
	change, mapping, err := h.gitChange(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request")
		return
	}
	if !hasGitCapability(r, mapping.Mode) {
		writeError(w, r, http.StatusForbidden, "CAPABILITY_DENIED", "Access denied")
		return
	}
	if mapping.Mode == policy.GitDeliveryProposal && h.ProposalProviders[mapping.Repository] == nil {
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
	pushed, err := h.GitTransport.PushBranch(r.Context(), change)
	if err != nil {
		var conflict *gitops.ConflictError
		if errors.As(err, &conflict) {
			writeError(w, r, http.StatusConflict, "GIT_CONFLICT", "Git conflict")
			return
		}
		writeError(w, r, http.StatusBadGateway, "GIT_UNAVAILABLE", "Git unavailable")
		return
	}
	result := map[string]any{"mode": mapping.Mode, "commit_sha": pushed.Commit, "branch": pushed.Branch, "file_path": change.Target.Path, "argocd_sync_verified": false}
	if mapping.Mode == policy.GitDeliveryProposal {
		provider := h.ProposalProviders[mapping.Repository]
		if provider == nil {
			writeError(w, r, http.StatusServiceUnavailable, "PROPOSAL_UNAVAILABLE", "Proposal provider unavailable")
			return
		}
		proposal, err := provider.OpenProposal(r.Context(), gitops.ProposalRequest{Change: change, Push: pushed})
		if err != nil {
			writeError(w, r, http.StatusBadGateway, "PROPOSAL_FAILED", "Proposal failed")
			return
		}
		result["proposal_url"] = proposal.URL
	}
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
