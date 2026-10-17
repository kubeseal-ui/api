// GitHub proposal adapter: opens a pull request for an already-pushed proposal branch via the GitHub
// REST API; the push itself is GoGitTransport's. The token is re-read from its Secret-mounted file per
// call and never appears in configuration; every failure aborts before returning a result.
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
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// otelTracer reads the global provider per call, so instrumentation is safe to mount before SetupTelemetry.
func otelTracer() trace.Tracer {
	return otel.Tracer("github.com/kubeseal-ui/api")
}

// propagationHeaderCarrier adapts http.Header to the OTel TextMapCarrier for outgoing requests.
type propagationHeaderCarrier struct{ header http.Header }

func (c propagationHeaderCarrier) Get(key string) string { return c.header.Get(key) }
func (c propagationHeaderCarrier) Set(key, value string) { c.header.Set(key, value) }
func (c propagationHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(c.header))
	for k := range c.header {
		keys = append(keys, k)
	}
	return keys
}

const githubAPIBase = "https://api.github.com"

// maxGitHubResponseBody bounds the PR response read into memory; the html_url we consume is a few hundred bytes.
const maxGitHubResponseBody = 1 << 20

type GitHubProposalOptions struct {
	// TokenFile is a Secret-mounted file holding a fine-grained personal access token.
	TokenFile string
	// BaseURL overrides the GitHub API root for GHES. Empty = api.github.com.
	BaseURL string
	// Client is the HTTP client for API calls; nil uses a default 30s-timeout client.
	Client *http.Client
}

// GitHubProposalProvider opens GitHub pull requests for pushed branches.
type GitHubProposalProvider struct {
	tokenFile string
	baseURL   string
	client    *http.Client
}

// NewGitHubProposalProvider validates configuration; a missing token file is a construction error, failing closed.
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

// verifyBranch confirms the proposal branch exists on the remote; a 404 means the push never created it.
func (p *GitHubProposalProvider) verifyBranch(ctx context.Context, owner, repo, branch, token string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/branches/%s", p.baseURL, owner, repo, url.PathEscape(branch))
	ctx, span := otelTracer().Start(ctx, "GitHub.GetBranch",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.request.method", http.MethodGet),
			attribute.String("url.full", url),
			attribute.String("server.address", p.baseURL),
			attribute.String("kubeseal_ui.adapter", "github"),
		))
	defer span.End()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build github branch request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	otel.GetTextMapPropagator().Inject(ctx, propagationHeaderCarrier{header: req.Header})
	resp, err := p.client.Do(req)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("github branch lookup: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Debug("github proposal adapter: close response body", "error", closeErr)
		}
	}()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGitHubResponseBody+1))
	if readErr != nil {
		return fmt.Errorf("read github response: %w", readErr)
	}
	if int64(len(raw)) > maxGitHubResponseBody {
		return fmt.Errorf("github response exceeded %d bytes", maxGitHubResponseBody)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("github branch %s does not exist: the push did not create it", branch)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github branch lookup failed: %s: %s", resp.Status, truncate(string(raw), 512))
	}
	return nil
}

// OpenProposal opens a pull request on the already-pushed proposal branch.
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
	// Push success does not guarantee the ref exists; opening against a missing branch turns a GitHub 422 into a readable error.
	if err = p.verifyBranch(ctx, owner, repo, request.Push.Branch, token); err != nil {
		return ProposalResult{}, err
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
	ctx, span := otelTracer().Start(ctx, "GitHub.CreatePullRequest",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("http.request.method", http.MethodPost),
			attribute.String("url.full", url),
			attribute.String("server.address", p.baseURL),
			attribute.String("kubeseal_ui.adapter", "github"),
		))
	defer span.End()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return ProposalResult{}, fmt.Errorf("build github request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	otel.GetTextMapPropagator().Inject(ctx, propagationHeaderCarrier{header: req.Header})
	resp, err := p.client.Do(req)
	if err != nil {
		span.RecordError(err)
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

// splitRepository splits "owner/repo"; anything but exactly two non-empty path segments is a config error.
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

// readTokenFile re-reads the PAT per call so Secret rotation needs no restart; the path is server-side
// policy from a Secret mount, never client input, hence the accepted gosec G304 finding.
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

func defaultProposalTitle(path string) string {
	return fmt.Sprintf("[kubeseal-ui] sealed secret update at %s", path)
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// githubPullRequest is the request body for POST /repos/{owner}/{repo}/pulls; githubPullRequestResponse is the subset we use.
type githubPullRequest struct {
	Title string `json:"title"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Body  string `json:"body"`
}

type githubPullRequestResponse struct {
	HTMLURL string `json:"html_url"`
}

func (r githubPullRequestResponse) GetHTMLURL() string { return r.HTMLURL }
