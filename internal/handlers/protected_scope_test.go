package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authmw "github.com/kubeseal-ui/api/internal/auth/middleware"
	"github.com/kubeseal-ui/api/internal/crypto"
	"github.com/kubeseal-ui/api/internal/gitops"
	"github.com/kubeseal-ui/api/internal/kubernetes"
	"github.com/kubeseal-ui/api/internal/policy"
)

// scopedIdentity builds an identity whose grants are split the way a policy
// document splits them: a global set, plus per-namespace grants.
func scopedIdentity(global []policy.Capability, scoped map[string][]policy.Capability) authmw.Identity {
	namespaceCapabilities := make(map[string][]string, len(scoped))
	for namespace, caps := range scoped {
		namespaceCapabilities[namespace] = capabilityNames(caps)
	}
	return authmw.Identity{
		Subject:               "user-1",
		Capabilities:          capabilityNames(global),
		NamespaceCapabilities: namespaceCapabilities,
	}
}

func capabilityNames(caps []policy.Capability) []string {
	names := make([]string, 0, len(caps))
	for _, cap := range caps {
		names = append(names, string(cap))
	}
	return names
}

// A grant scoped to one namespace authorizes that namespace and nothing else — the property that
// makes the namespace dimension worth having.
func TestScopedGrantAuthorizesOnlyItsNamespace(t *testing.T) {
	k8s := protectedK8s{
		secrets: []kubernetes.SealedSecret{
			{Name: "api", Namespace: "payments"},
			{Name: "api", Namespace: "development"},
		},
	}
	h := NewProtectedHandlers(k8s, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.MetadataRead}})

	listed := httptest.NewRecorder()
	h.SecretsHandler(listed, protectedRequest(http.MethodGet, "/api/v1/secrets?namespace=payments", "", identity))
	if listed.Code != http.StatusOK {
		t.Fatalf("payments status = %d, want 200: %s", listed.Code, listed.Body.String())
	}

	denied := httptest.NewRecorder()
	h.SecretsHandler(denied, protectedRequest(http.MethodGet, "/api/v1/secrets?namespace=development", "", identity))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("development status = %d, want 403", denied.Code)
	}
	assertErrorEnvelope(t, denied, "CAPABILITY_DENIED", "Access denied", "")
}

// The namespace listing is filtered rather than gatekept: a caller with a grant in one namespace
// sees that one, not a 403 and not everything.
func TestNamespacesHandlerListsOnlyGrantedNamespaces(t *testing.T) {
	k8s := protectedK8s{namespaces: []kubernetes.Namespace{{Name: "payments"}, {Name: "development"}}}
	h := NewProtectedHandlers(k8s, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.MetadataRead, policy.SecretSeal}})

	rr := httptest.NewRecorder()
	h.NamespacesHandler(rr, protectedRequest(http.MethodGet, "/api/v1/namespaces", "", identity))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Namespaces []kubernetes.Namespace `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Namespaces) != 1 || body.Namespaces[0].Name != "payments" {
		t.Fatalf("namespaces = %+v, want just payments", body.Namespaces)
	}
	// The per-namespace capabilities travel with the namespace so the UI need not probe for a 403.
	if got := body.Namespaces[0].Capabilities; len(got) != 2 {
		t.Fatalf("capabilities = %v, want metadata:read and secret:seal", got)
	}
}

// An unscoped listing is the one place a caller can ask about namespaces it cannot name, so the
// results — not just the gate — have to be filtered.
func TestSecretsHandlerFiltersAnUnscopedListing(t *testing.T) {
	k8s := protectedK8s{
		secrets: []kubernetes.SealedSecret{
			{Name: "api", Namespace: "payments"},
			{Name: "api", Namespace: "development"},
			{Name: "db", Namespace: "payments"},
		},
	}
	h := NewProtectedHandlers(k8s, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.MetadataRead}})

	rr := httptest.NewRecorder()
	h.SecretsHandler(rr, protectedRequest(http.MethodGet, "/api/v1/secrets", "", identity))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Secrets []kubernetes.SealedSecret `json:"secrets"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Secrets) != 2 {
		t.Fatalf("secrets = %+v, want the two in payments", body.Secrets)
	}
	for _, secret := range body.Secrets {
		if secret.Namespace != "payments" {
			t.Errorf("listing leaked a secret from %q", secret.Namespace)
		}
	}
}

// A caller with no grant anywhere is refused before the listing, rather than handed an empty one
// that looks like "nothing exists".
func TestUnscopedListingRequiresAGrantSomewhere(t *testing.T) {
	h := NewProtectedHandlers(protectedK8s{secrets: []kubernetes.SealedSecret{{Name: "api", Namespace: "payments"}}}, nil, false)
	rr := httptest.NewRecorder()
	h.SecretsHandler(rr, protectedRequest(http.MethodGet, "/api/v1/secrets", "", scopedIdentity(nil, nil)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

// The path picker offers destinations: a namespace the caller cannot read is not a destination,
// whatever the Git mapping says about it.
func TestGitPathsHandlerOffersOnlyGrantedNamespaces(t *testing.T) {
	store := policy.NewPolicyStore()
	for _, namespace := range []string{"payments", "development"} {
		if err := store.SetGitMapping(policy.GitMapping{
			Namespace: namespace, Repository: "platform/config", Branch: "main",
			PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "git-auth",
			Mode: policy.GitDeliveryDirect,
		}); err != nil {
			t.Fatal(err)
		}
	}
	h := NewProtectedHandlersWithGitOps(store, gitops.NewLocalTransport(), nil, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.MetadataRead, policy.SecretSeal}})

	rr := httptest.NewRecorder()
	h.GitPathsHandler(rr, protectedRequest(http.MethodGet, "/api/v1/gitops/paths", "", identity))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Namespaces []struct {
			Namespace string `json:"namespace"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Namespaces) != 1 || body.Namespaces[0].Namespace != "payments" {
		t.Fatalf("paths = %+v, want just payments", body.Namespaces)
	}
}

// The wildcard mapping is not a namespace, so the namespace filter does not apply to it: it is the
// mapping every unmapped namespace falls back to, and the client resolves it by the same fallback. A
// deployment configured with a single wildcard mapping — the common shape — must still see it, or the
// delivery panel has no mode to name; a real namespace the caller cannot read stays hidden.
func TestGitPathsHandlerKeepsTheWildcardMapping(t *testing.T) {
	store := policy.NewPolicyStore()
	for _, namespace := range []string{policy.AnyNamespace, "payments", "development"} {
		if err := store.SetGitMapping(policy.GitMapping{
			Namespace: namespace, Repository: "YogaNovvaindra/kube", Branch: "main",
			PathTemplate: "{namespace}/{name}-cred.yml", AuthRef: "git-auth",
			Mode: policy.GitDeliveryDirect,
		}); err != nil {
			t.Fatal(err)
		}
	}
	h := NewProtectedHandlersWithGitOps(store, gitops.NewLocalTransport(), nil, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.MetadataRead}})

	rr := httptest.NewRecorder()
	h.GitPathsHandler(rr, protectedRequest(http.MethodGet, "/api/v1/gitops/paths", "", identity))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Namespaces []struct {
			Namespace string `json:"namespace"`
			Mode      string `json:"mode"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	modes := make(map[string]string, len(body.Namespaces))
	for _, entry := range body.Namespaces {
		modes[entry.Namespace] = entry.Mode
	}
	if modes[policy.AnyNamespace] != string(policy.GitDeliveryDirect) {
		t.Fatalf("wildcard entry = %q, want a direct mapping: %+v", modes[policy.AnyNamespace], body.Namespaces)
	}
	if _, ok := modes["payments"]; !ok {
		t.Fatalf("payments holds metadata:read and is missing: %+v", body.Namespaces)
	}
	if _, ok := modes["development"]; ok {
		t.Fatalf("development is readable nowhere and must not be offered: %+v", body.Namespaces)
	}
}

// The listing carries the mapping's template raw and its allowed paths as directories. A
// per-namespace response has no Secret name to render `{name}` with, so a rendered path here could
// only ever be empty; the client substitutes the name it has and joins it to a directory, which is
// why the entry is a directory prefix rather than a destination.
func TestGitPathsHandlerCarriesTheRawTemplateAndDirectories(t *testing.T) {
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace: "payments", Repository: "platform/config", Branch: "main",
		PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "git-auth",
		Mode: policy.GitDeliveryDirect, AllowedPaths: []string{"custom/apps", "apps/{namespace}"},
	}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, gitops.NewLocalTransport(), nil, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.MetadataRead}})

	rr := httptest.NewRecorder()
	h.GitPathsHandler(rr, protectedRequest(http.MethodGet, "/api/v1/gitops/paths", "", identity))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Namespaces []struct {
			PathTemplate string   `json:"path_template"`
			AllowedPaths []string `json:"allowed_paths"`
		} `json:"namespaces"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Namespaces) != 1 {
		t.Fatalf("paths = %+v, want one entry", body.Namespaces)
	}
	if got := body.Namespaces[0].PathTemplate; got != "clusters/{namespace}/{name}.yaml" {
		t.Fatalf("path_template = %q, want the mapping's own template", got)
	}
	if got := body.Namespaces[0].AllowedPaths; len(got) != 2 || got[0] != "custom/apps" || got[1] != "apps/{namespace}" {
		t.Fatalf("allowed_paths = %+v, want the mapping's directories", got)
	}
}

// The seal gate fires before the body is read, so a caller who holds secret:seal nowhere is refused
// without their manifest being parsed. A body that is not even valid JSON is the proof: 403 means the
// decode never ran, 400 would mean it did.
func TestEncryptRefusesBeforeDecodingForACallerWhoCanSealNowhere(t *testing.T) {
	h := NewProtectedHandlers(nil, nil, false)
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", "{not json", protectedIdentity()))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — the body was parsed for an unauthorized caller", rr.Code)
	}
}

// Holding secret:seal somewhere is not an answer to "may this caller seal here"; the second gate
// asks the namespace question once the body names it.
func TestEncryptRequiresSealCapabilityInTheTargetNamespace(t *testing.T) {
	// A crypto wrapper, not nil: the refusal must come from the namespace check, not the earlier
	// "crypto unavailable" branch.
	h := NewProtectedHandlers(nil, crypto.New(protectedCertProvider{}, nil), false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"payments": {policy.SecretSeal}})
	body := `{"namespace":"development","name":"api","yaml":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: api\n  namespace: development\n"}`
	rr := httptest.NewRecorder()
	h.EncryptHandler(rr, protectedRequest(http.MethodPost, "/api/v1/secrets/encrypt", body, identity))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
	}
	assertErrorEnvelope(t, rr, "CAPABILITY_DENIED", "Access denied", "")
}

// Delivery is an act in the namespace the mapping resolved to, so the grant has to be there — the
// support case the whole change exists for: a group mapped to platform-admin plus a delivery role
// scoped to one namespace.
func TestGitOpsDeliverRequiresCapabilityInTheMappedNamespace(t *testing.T) {
	store := policy.NewPolicyStore()
	if err := store.SetGitMapping(policy.GitMapping{
		Namespace: "payments", Repository: "platform", Branch: "main",
		PathTemplate: "clusters/{namespace}/{name}.yaml", AuthRef: "auth", Mode: policy.GitDeliveryDirect,
	}); err != nil {
		t.Fatal(err)
	}
	h := NewProtectedHandlersWithGitOps(store, gitops.NewLocalTransport(), nil, nil, false)
	identity := scopedIdentity(nil, map[string][]policy.Capability{"development": {policy.GitOpsPush}})

	rr := httptest.NewRecorder()
	h.GitOpsDeliverHandler(rr, protectedRequest(http.MethodPost, "/api/v1/gitops/deliver",
		gitChangeBody(t, "payments", "api", sealedManifest("payments", "api"), "abc"), identity))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "CAPABILITY_DENIED") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}
