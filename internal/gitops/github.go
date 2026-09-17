// GitHub proposal adapter: opens a pull request for an already-pushed
// proposal branch via the GitHub REST API.
//
// Phase 5 deliverable. The push itself is performed by GoGitTransport;
// this adapter only creates the host review object, so it is invoked after
// PushBranch succeeds. It is wired behind the "github-pr" adapter name
// chosen in Helm values (policy.GitMappingSpec.ProposalAdapterName) and
// constructed from env vars at boot.
//
// Token handling: GITOPS_PROPOSAL_GITHUB_TOKEN_FILE points at a
// Secret-mounted file (fine-grained PAT with Contents: Read+Write,
// Metadata: Read). The token is read on every OpenProposal call so a
// rotated Secret takes effect without a restart; tokens never appear in
// configuration. GITOPS_PROPOSAL_GITHUB_BASE_URL overrides the API root
// for GitHub Enterprise Server (empty = api.github.com).
//
// Fail-closed: an unknown repository shape, a missing token, or a
// non-2xx response aborts before returning a result, so a misconfigured
// adapter never surfaces a misleading "success".
package gitops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// githubAPIBase is the default GitHub REST endpoint.
const githubAPIBase = "https://api.github.com"

// maxGitHubResponseBody bounds the PR creation response read into memory.
// The html_url we consume is a few hundred bytes; the limit only stops an
// unexpected multi-megabyte body from being buffered whole.
const maxGitHubResponseBody = 1 << 20

// GitHubProposalOptions configures the GitHub proposal adapter.
type GitHubProposalOptions struct {
	// TokenFile is the path to a Secret-mounted file holding a
	// fine-grained personal access token. Required.
	TokenFile string
	// BaseURL overrides the GitHub API root for GHES. Empty = api.github.com.
	BaseURL string
	// Client is the HTTP client used for API calls. May be nil to use
	// a default 30s-timeout client. Tests inject an httptest server URL.
	Client *http.Client
}

// GitHubProposalProvider opens GitHub pull requests for pushed branches.
// Implements the ProposalProvider interface.
type GitHubProposalProvider struct {
	tokenFile string
	baseURL   string
	client    *http.Client
}

// NewGitHubProposalProvider builds the adapter and validates configuration.
// A missing token file is a construction error: the API fails closed if
// proposal mode cannot be satisfied.
func NewGitHubProposalProvider(opts GitHubProposalOptions) (*GitHubProposalProvider, error) {
	if opts.TokenFile == "" {
		return nil, errors.New("github proposal provider requires a token file")
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = githubAPIBase
	}
	return &GitHubProposalProvider{tokenFile: opts.TokenFile, baseURL: strings.TrimRight(baseURL, "/"), client: client}, nil
}

// OpenProposal opens a pull request on the already-pushed proposal branch.
// The push commit must exist on the remote because PushBranch succeeded
// before this call.
func (p *GitHubProposalProvider) OpenProposal(ctx context.Context, request ProposalRequest) (ProposalResult, error) {
	if request.Push.Branch == "" || request.Push.Commit == "" {
		return ProposalResult{}, errors.New("proposal requires a pushed branch and commit")
	}
	owner, repo, err := splitRepository(request.Change.Target.Repository)
	if err != nil {
		return ProposalResult{}, err
	}
	token, err := readTokenFile(p.tokenFile)
	if err != nil {
		return ProposalResult{}, fmt.Errorf("read github token: %w", err)
	}
	title := request.Title
	if title == "" {
		title = defaultProposalTitle(request.Change.Target.Path)
	}
	body := request.Body
	if body == "" {
		body = fmt.Sprintf("Sealed secret update for `%s`, proposed by kubeseal-ui.\n\nCommit: `%s`", strings.TrimPrefix(request.Change.Target.Path, "clusters/"), request.Push.Commit)
	}
	prReq := githubPullRequest{
		Title: title,
		Head:  request.Push.Branch,
		Base:  request.Change.Target.Branch,
		Body:  body,
	}
	bodyBytes, err := json.Marshal(prReq)
	if err != nil {
		return ProposalResult{}, fmt.Errorf("encode github pr request: %w", err)
	}
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", p.baseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return ProposalResult{}, fmt.Errorf("build github request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return ProposalResult{}, fmt.Errorf("github api call: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("github proposal adapter: close response body", "error", closeErr)
		}
	}()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGitHubResponseBody+1))
	if readErr != nil {
		return ProposalResult{}, fmt.Errorf("read github response: %w", readErr)
	}
	if int64(len(raw)) > maxGitHubResponseBody {
		return ProposalResult{}, fmt.Errorf("github response exceeded %d bytes", maxGitHubResponseBody)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ProposalResult{}, fmt.Errorf("github pr creation failed: %s: %s", resp.Status, truncate(string(raw), 512))
	}
	var pr githubPullRequestResponse
	if err := json.Unmarshal(raw, &pr); err != nil {
		return ProposalResult{}, fmt.Errorf("decode github pr response: %w", err)
	}
	return ProposalResult{
		URL:        pr.GetHTMLURL(),
		Repository: request.Change.Target.Repository,
		Branch:     request.Push.Branch,
		Commit:     request.Push.Commit,
	}, nil
}

// splitRepository splits "owner/repo" into its parts. A GitHub repository
// reference is exactly two path segments; anything else is a config error.
func splitRepository(repository string) (string, string, error) {
	repository = strings.TrimSpace(repository)
	if repository == "" {
		return "", "", errors.New("repository is required for a github proposal")
	}
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("github repository %q must be \"owner/repo\"", repository)
	}
	return parts[0], parts[1], nil
}

// readTokenFile reads a pat file per call so Secret rotation takes effect
// without a restart. Leading/trailing whitespace (including newlines) is
// trimmed. An empty token is an error. The path is server-side policy: a
// Secret mount path from configuration, never client input, so the gosec
// G304 finding is accepted at the call site.
func readTokenFile(path string) (string, error) { // #nosec G304
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("github token file is empty")
	}
	return token, nil
}

// defaultProposalTitle builds a human-readable PR title from the sealed
// secret path when the caller did not supply one.
func defaultProposalTitle(path string) string {
	return fmt.Sprintf("[kubeseal-ui] sealed secret update at %s", path)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// githubPullRequest is the request body for POST /repos/{owner}/{repo}/pulls.
type githubPullRequest struct {
	Title string `json:"title"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Body  string `json:"body"`
}

// githubPullRequestResponse is the subset of the GitHub PR response we use.
type githubPullRequestResponse struct {
	HTMLURL string `json:"html_url"`
}

func (r githubPullRequestResponse) GetHTMLURL() string { return r.HTMLURL }
