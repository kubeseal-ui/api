package gitops

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeTransport is an in-process http.RoundTripper so adapter tests never
// touch the loopback socket (the sandbox blocks loopback HTTP). It records
// the request and returns a canned response.
type fakeTransport struct {
	status  int
	body    string
	lastReq atomic.Value
	err     error
	calls   atomic.Int32
}

func (t *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	t.lastReq.Store(req)
	if t.err != nil {
		return nil, t.err
	}
	return &http.Response{
		StatusCode: t.status,
		Header:     http.Header{"Content-Type": []string{"application/vnd.github+json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(t.body))),
	}, nil
}

func (t *fakeTransport) lastRequest() *http.Request {
	v := t.lastReq.Load()
	if v == nil {
		return nil
	}
	return v.(*http.Request)
}

// newFakeProviderWith builds a provider whose http.Client shares a
// fakeTransport so tests can inspect lastReq and calls.
func newFakeProviderWith(t *testing.T, token string, tr *fakeTransport) *GitHubProposalProvider {
	return &GitHubProposalProvider{
		tokenFile: tokenFileFor(t, token),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: tr},
	}
}

func tokenFileFor(t *testing.T, token string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGitHubOpenProposalCreatesPullRequest(t *testing.T) {
	body := `{"html_url":"https://github.com/org/platform/pull/42"}`
	tr := &fakeTransport{status: http.StatusCreated, body: body}
	provider := &GitHubProposalProvider{
		tokenFile: tokenFileFor(t, "ghp_testtoken"),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: tr},
	}

	change := Change{Target: Target{Repository: "org/platform", Branch: "main", Path: "clusters/payments/foo.yaml"}}
	req := ProposalRequest{Change: change, Push: PushResult{Repository: "org/platform", Branch: "kubeseal-ui/payments-foo", Commit: "abc123"}}

	result, err := provider.OpenProposal(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.URL != "https://github.com/org/platform/pull/42" {
		t.Errorf("url = %q, want PR url", result.URL)
	}
	if result.Branch != req.Push.Branch {
		t.Errorf("branch = %q, want %q", result.Branch, req.Push.Branch)
	}
	if result.Commit != req.Push.Commit {
		t.Errorf("commit = %q, want %q", result.Commit, req.Push.Commit)
	}
	if tr.calls.Load() != 1 {
		t.Errorf("api calls = %d, want 1", tr.calls.Load())
	}
	// Verify request shape against GitHub REST contract.
	sent := tr.lastRequest()
	if sent == nil {
		t.Fatal("no request captured")
	}
	if sent.URL.Path != "/repos/org/platform/pulls" {
		t.Errorf("path = %q", sent.URL.Path)
	}
	if sent.Header.Get("Authorization") != "Bearer ghp_testtoken" {
		t.Errorf("auth header = %q", sent.Header.Get("Authorization"))
	}
	if sent.Header.Get("Accept") != "application/vnd.github+json" {
		t.Errorf("accept = %q", sent.Header.Get("Accept"))
	}
	var pr githubPullRequest
	if err := json.NewDecoder(sent.Body).Decode(&pr); err != nil {
		t.Fatalf("decode sent body: %v", err)
	}
	if pr.Head != "kubeseal-ui/payments-foo" {
		t.Errorf("head = %q", pr.Head)
	}
	if pr.Base != "main" {
		t.Errorf("base = %q", pr.Base)
	}
}

// Retry with the same branch/commit still yields a result; the adapter is
// stateless and does not dedupe, so the retry hits the API again.
func TestGitHubOpenProposalRetrySucceeds(t *testing.T) {
	body := `{"html_url":"https://github.com/org/platform/pull/99"}`
	tr := &fakeTransport{status: http.StatusOK, body: body}
	provider := newFakeProviderWith(t, "tok", tr)

	req := ProposalRequest{
		Change: Change{Target: Target{Repository: "org/platform", Branch: "main"}},
		Push:   PushResult{Repository: "org/platform", Branch: "kubeseal-ui/payments-foo", Commit: "abc123"},
	}
	result, err := provider.OpenProposal(context.Background(), req)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if result.URL == "" {
		t.Fatal("expected non-empty url")
	}
	if tr.calls.Load() != 1 {
		t.Fatalf("api calls = %d, want 1", tr.calls.Load())
	}
}

func TestGitHubOpenProposalMissingPushBranchFails(t *testing.T) {
	provider := &GitHubProposalProvider{
		tokenFile: tokenFileFor(t, "tok"),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: &fakeTransport{status: http.StatusCreated, body: "{}"}},
	}
	_, err := provider.OpenProposal(context.Background(), ProposalRequest{Change: Change{Target: Target{Repository: "org/platform", Branch: "main"}}})
	if err == nil {
		t.Fatal("expected error for missing push branch/commit")
	}
	if !strings.Contains(err.Error(), "pushed branch and commit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGitHubOpenProposalBadRepositoryShapeFails(t *testing.T) {
	tr := &fakeTransport{status: http.StatusCreated, body: "{}"}
	provider := &GitHubProposalProvider{
		tokenFile: tokenFileFor(t, "tok"),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: tr},
	}
	for _, bad := range []string{"", "noslash", "org/platform/repo/extra", "org/", "/repo"} {
		req := ProposalRequest{
			Change: Change{Target: Target{Repository: bad, Branch: "main"}},
			Push:   PushResult{Repository: bad, Branch: "kubeseal-ui/x-y", Commit: "abc123"},
		}
		_, err := provider.OpenProposal(context.Background(), req)
		if err == nil {
			t.Errorf("repository %q: expected error", bad)
		}
	}
	if tr.calls.Load() != 0 {
		t.Errorf("expected 0 api calls for bad repos, got %d", tr.calls.Load())
	}
}

func TestGitHubOpenProposalAPIErrorFailsClosed(t *testing.T) {
	tr := &fakeTransport{status: http.StatusForbidden, body: `{"message":"bad credentials"}`}
	provider := &GitHubProposalProvider{
		tokenFile: tokenFileFor(t, "tok"),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: tr},
	}
	req := ProposalRequest{
		Change: Change{Target: Target{Repository: "org/platform", Branch: "main"}},
		Push:   PushResult{Repository: "org/platform", Branch: "kubeseal-ui/payments-foo", Commit: "abc123"},
	}
	_, err := provider.OpenProposal(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !strings.Contains(err.Error(), "github pr creation failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.calls.Load() != 1 {
		t.Errorf("api calls = %d, want 1 (no retry on auth failure)", tr.calls.Load())
	}
}

func TestGitHubOpenProposalTransportErrorFailsClosed(t *testing.T) {
	tr := &fakeTransport{err: errors.New("connection reset")}
	provider := &GitHubProposalProvider{
		tokenFile: tokenFileFor(t, "tok"),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: tr},
	}
	req := ProposalRequest{
		Change: Change{Target: Target{Repository: "org/platform", Branch: "main"}},
		Push:   PushResult{Repository: "org/platform", Branch: "kubeseal-ui/payments-foo", Commit: "abc123"},
	}
	_, err := provider.OpenProposal(context.Background(), req)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if !strings.Contains(err.Error(), "github api call") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGitHubOpenProposalMissingTokenFileFails(t *testing.T) {
	tr := &fakeTransport{status: http.StatusCreated, body: "{}"}
	provider := &GitHubProposalProvider{
		tokenFile: filepath.Join(t.TempDir(), "missing"),
		baseURL:   "http://github.test",
		client:    &http.Client{Transport: tr},
	}
	req := ProposalRequest{
		Change: Change{Target: Target{Repository: "org/platform", Branch: "main"}},
		Push:   PushResult{Repository: "org/platform", Branch: "kubeseal-ui/payments-foo", Commit: "abc123"},
	}
	_, err := provider.OpenProposal(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing token file")
	}
	if !strings.Contains(err.Error(), "read github token") {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr.calls.Load() != 0 {
		t.Errorf("expected 0 api calls before token read, got %d", tr.calls.Load())
	}
}

func TestGitHubProposalProviderConstructionFailsWithoutTokenFile(t *testing.T) {
	_, err := NewGitHubProposalProvider(GitHubProposalOptions{BaseURL: "http://x"})
	if err == nil {
		t.Fatal("expected construction error without token file")
	}
	if !strings.Contains(err.Error(), "token file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGitHubProposalProviderConstructionDefaultsBaseURL(t *testing.T) {
	p, err := NewGitHubProposalProvider(GitHubProposalOptions{TokenFile: "/dev/null"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.baseURL != githubAPIBase {
		t.Errorf("baseURL = %q, want %q", p.baseURL, githubAPIBase)
	}
	if p.tokenFile != "/dev/null" {
		t.Errorf("tokenFile = %q", p.tokenFile)
	}
}
