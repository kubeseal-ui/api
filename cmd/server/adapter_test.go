package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubeseal-ui/api/internal/config"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/policy"
)

// tokenFileFor writes a token to a temp file so adapter construction has
// a path it can validate at boot.
func tokenFileFor(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseProposalAdapterSpecs(t *testing.T) {
	specs, err := parseProposalAdapterSpecs("github-pr:github:/var/run/secrets/git/proposal/token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("specs = %d, want 1", len(specs))
	}
	if specs[0].Name != "github-pr" || specs[0].Type != "github" || specs[0].TokenFile != "/var/run/secrets/git/proposal/token" {
		t.Fatalf("unexpected spec: %+v", specs[0])
	}
	if specs[0].BaseURL != "" {
		t.Errorf("BaseURL = %q, want empty (api.github.com)", specs[0].BaseURL)
	}

	ghes, err := parseProposalAdapterSpecs("github-ghes:github:/var/run/secrets/git/proposal/token:https://github.example.com/api/v3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ghes) != 1 || ghes[0].BaseURL != "https://github.example.com/api/v3" {
		t.Fatalf("GHES spec not parsed: %+v", ghes)
	}
}

func TestParseProposalAdapterSpecsEmptyMeansNoAdapters(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		specs, err := parseProposalAdapterSpecs(raw)
		if err != nil {
			t.Fatalf("raw %q: unexpected error: %v", raw, err)
		}
		if len(specs) != 0 {
			t.Fatalf("raw %q: specs = %d, want 0", raw, len(specs))
		}
	}
}

func TestParseProposalAdapterSpecsFailsClosed(t *testing.T) {
	cases := map[string]string{
		"missing token file (bare type)": "github-pr:github",
		"missing type":                   "github-pr::/var/run/secrets/token",
		"missing name":                   ":github:/var/run/secrets/token",
		"duplicate name":                 "github-pr:github:/a/token,github-pr:github:/b/token",
		"empty token file":               "github-pr:github:",
		"blank name with padding":        " :github:/a/token",
		"empty token file with base url": "github-pr:github::https://github.example.com/api/v3",
	}
	for name, raw := range cases {
		if _, err := parseProposalAdapterSpecs(raw); err == nil {
			t.Errorf("%s (%q): expected an error", name, raw)
		}
	}
}

func TestProposalAdaptersRegistersConfiguredGitHubAdapter(t *testing.T) {
	tokenFile := tokenFileFor(t)
	adapters, err := proposalAdapters(&config.Config{GitOpsProposalAdapters: "github-pr:github:" + tokenFile})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := adapters["github-pr"]; !ok {
		t.Fatalf("github-pr adapter not registered: %v", adapters)
	}
	var _ gitops.ProposalProvider = adapters["github-pr"]
}

func TestProposalAdaptersEmptyConfigRegistersNothing(t *testing.T) {
	adapters, err := proposalAdapters(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(adapters) != 0 {
		t.Fatalf("adapters = %v, want none", adapters)
	}
}

func TestProposalAdaptersUnknownTypeFailsClosed(t *testing.T) {
	_, err := proposalAdapters(&config.Config{GitOpsProposalAdapters: "gitlab-mr:gitlab:/var/run/secrets/token"})
	if err == nil {
		t.Fatal("expected an error for an unknown adapter type")
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProposalAdaptersMalformedEntryFailsClosed(t *testing.T) {
	if _, err := proposalAdapters(&config.Config{GitOpsProposalAdapters: "github-pr:github"}); err == nil {
		t.Fatal("expected an error for a malformed entry")
	}
}

// TestRouterRefusesBootWhenProposalNamespaceNamesUnregisteredAdapter pins
// the fail-closed contract end to end: a proposal namespace that names an
// adapter no registry entry provides must stop the API from booting rather
// than serving deliveries with an unusable provider.
func TestRouterRefusesBootWhenProposalNamespaceNamesUnregisteredAdapter(t *testing.T) {
	_, err := newRouter(routerOptions{
		logger:    testLogger(),
		cfg:       testConfig(),
		k8s:       testK8s(),
		transport: gitops.NewLocalTransport(),
		mappingSpecs: []policy.GitMappingSpec{
			{Namespace: "staging", Repository: "org/platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "platform-cred", Mode: policy.GitDeliveryProposal, ProposalAdapterName: "github-pr"},
		},
		adapters: map[string]gitops.ProposalProvider{},
	})
	if err == nil {
		t.Fatal("expected boot to fail when a proposal namespace names an unregistered adapter")
	}
	if !strings.Contains(err.Error(), "unknown proposal adapter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRouterBootsWithRegisteredAdapter is the positive counterpart: the
// same mapping seeds successfully once the adapter registry holds the name.
func TestRouterBootsWithRegisteredAdapter(t *testing.T) {
	tokenFile := tokenFileFor(t)
	adapters, err := proposalAdapters(&config.Config{GitOpsProposalAdapters: "github-pr:github:" + tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	router, err := newRouter(routerOptions{
		logger:    testLogger(),
		cfg:       testConfig(),
		k8s:       testK8s(),
		transport: gitops.NewLocalTransport(),
		mappingSpecs: []policy.GitMappingSpec{
			{Namespace: "staging", Repository: "org/platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "platform-cred", Mode: policy.GitDeliveryProposal, ProposalAdapterName: "github-pr"},
			{Namespace: "payments", Repository: "org/platform", Branch: "main", PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "platform-cred", Mode: policy.GitDeliveryDirect},
		},
		adapters: adapters,
	})
	if err != nil {
		t.Fatalf("boot failed: %v", err)
	}
	if router == nil {
		t.Fatal("nil router")
	}
}
