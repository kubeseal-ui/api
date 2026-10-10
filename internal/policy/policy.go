// Package policy implements the capability registry, role definitions, namespace Git
// mappings, and authorization logic for the kubeseal-ui API.
//
// Grants are namespace-scoped: a group rule names a role and the namespaces it applies in,
// and an identity's capabilities in a namespace are the union of its rules scoped to that
// namespace and its rules scoped to "*". With no policy document loaded — see document.go —
// the store falls back to the older behaviour where an OIDC group named exactly after a
// role granted that role everywhere.
package policy

import (
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"sync"
	"text/template"

	"github.com/kubeseal-ui/api/internal/gitops"
)

// Capability is a named permission.
type Capability string

const (
	MetadataRead  Capability = "metadata:read"
	SecretSeal    Capability = "secret:seal"
	SecretDecrypt Capability = "secret:decrypt"
	GitOpsPropose Capability = "gitops:propose"
	GitOpsPush    Capability = "gitops:push"
	AccessManage  Capability = "access:manage"
)

// All is every known capability, in the canonical order orderedCapabilities renders in.
var All = []Capability{
	MetadataRead,
	SecretSeal,
	SecretDecrypt,
	GitOpsPropose,
	GitOpsPush,
	AccessManage,
}

func (c Capability) Valid() bool {
	for _, known := range All {
		if c == known {
			return true
		}
	}
	return false
}

type Role struct {
	Name         string
	Capabilities []Capability
}

var (
	RoleViewer = Role{
		Name: "viewer",
		Capabilities: []Capability{
			MetadataRead,
		},
	}

	RoleEditor = Role{
		Name: "editor",
		Capabilities: []Capability{
			MetadataRead,
			SecretSeal,
		},
	}

	RoleSecretManager = Role{
		Name: "secret-manager",
		Capabilities: []Capability{
			MetadataRead,
			SecretSeal,
			SecretDecrypt,
		},
	}

	// Delivery roles are deliberately separate from the editing roles: neither bundle
	// carries seal or decrypt. Holding gitops:push lets a user deliver a manifest someone
	// else sealed; it does not let them read plaintext or create secrets.
	RoleReleaseProposer = Role{
		Name: "release-proposer",
		Capabilities: []Capability{
			MetadataRead,
			GitOpsPropose,
		},
	}

	RoleReleasePusher = Role{
		Name: "release-pusher",
		Capabilities: []Capability{
			MetadataRead,
			GitOpsPush,
		},
	}

	RolePlatformAdmin = Role{
		Name: "platform-admin",
		Capabilities: []Capability{
			MetadataRead,
			SecretSeal,
			AccessManage,
		},
	}

	BuiltInRoles = []Role{
		RoleViewer,
		RoleEditor,
		RoleSecretManager,
		RoleReleaseProposer,
		RoleReleasePusher,
		RolePlatformAdmin,
	}
)

func BuiltInRoleNames() []string {
	names := make([]string, len(BuiltInRoles))
	for i, r := range BuiltInRoles {
		names[i] = r.Name
	}
	return names
}

func IsBuiltInRole(name string) bool {
	for _, r := range BuiltInRoles {
		if r.Name == name {
			return true
		}
	}
	return false
}

func GetBuiltInRole(name string) (Role, bool) {
	for _, r := range BuiltInRoles {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

// NewCustomRole rejects unknown capabilities and names that collide with a built-in.
func NewCustomRole(name string, caps []Capability) (Role, error) {
	if IsBuiltInRole(name) {
		return Role{}, fmt.Errorf("role name %q conflicts with built-in role", name)
	}
	seen := map[Capability]bool{}
	for _, c := range caps {
		if !c.Valid() {
			return Role{}, fmt.Errorf("unknown capability %q", c)
		}
		seen[c] = true
	}
	uniq := make([]Capability, 0, len(seen))
	for c := range seen {
		uniq = append(uniq, c)
	}
	return Role{Name: name, Capabilities: uniq}, nil
}

// Identity represents an authenticated principal with capabilities.
type Identity struct {
	Subject  string
	Email    string
	Name     string
	Username string
	Groups   []string
	// Roles are the role names assigned to this identity.
	Roles []string
}

// Capabilities is the additive union of the capabilities of the built-in roles in Roles.
func (i Identity) Capabilities() []Capability {
	seen := map[Capability]bool{}
	for _, roleName := range i.Roles {
		if role, ok := GetBuiltInRole(roleName); ok {
			for _, c := range role.Capabilities {
				seen[c] = true
			}
		}
	}
	caps := make([]Capability, 0, len(seen))
	for c := range seen {
		caps = append(caps, c)
	}
	return caps
}

func (i Identity) Has(c Capability) bool {
	for _, cap := range i.Capabilities() {
		if cap == c {
			return true
		}
	}
	return false
}

// GitDeliveryMode is how sealed secrets reach Git.
type GitDeliveryMode string

const (
	GitDeliveryDirect   GitDeliveryMode = "direct"
	GitDeliveryProposal GitDeliveryMode = "proposal"
)

type GitMapping struct {
	Namespace    string
	Repository   string
	Branch       string
	PathTemplate string // e.g. "clusters/prod/{namespace}/{name}.yaml"
	AuthRef      string
	Mode         GitDeliveryMode
	// ProposalAdapter is required when Mode is proposal. Instance wiring (tests,
	// programmatic setup) populates the adapter; values-driven seeding populates
	// ProposalAdapterName instead.
	ProposalAdapter     gitops.ProposalProvider
	ProposalAdapterName string
	// AllowedPaths optionally lists directory prefixes (relative to the repo root) users may
	// target for new sealed secrets; empty means only the rendered PathTemplate is allowed.
	AllowedPaths []string
}

func (g GitMapping) Validate() error {
	if g.Namespace == "" {
		return errors.New("namespace is required")
	}
	if g.Repository == "" {
		return errors.New("repository is required")
	}
	if g.Branch == "" {
		return errors.New("branch is required")
	}
	if g.PathTemplate == "" {
		return errors.New("path template is required")
	}
	if g.AuthRef == "" {
		return errors.New("auth reference is required")
	}
	if !strings.Contains(g.PathTemplate, "{namespace}") || !strings.Contains(g.PathTemplate, "{name}") {
		return errors.New("path template must contain {namespace} and {name}")
	}
	if strings.ContainsAny(g.PathTemplate, "\\\x00") || strings.Contains(g.PathTemplate, "..") || strings.HasPrefix(g.PathTemplate, "/") {
		return errors.New("path template contains unsafe path")
	}
	if strings.Contains(g.PathTemplate, "{{") || strings.Contains(g.PathTemplate, "}}") {
		return errors.New("path template uses invalid template syntax")
	}
	templateWithoutPlaceholders := strings.ReplaceAll(strings.ReplaceAll(g.PathTemplate, "{namespace}", ""), "{name}", "")
	if strings.ContainsAny(templateWithoutPlaceholders, "{}") {
		return errors.New("path template contains unknown placeholder")
	}
	parsed := strings.ReplaceAll(strings.ReplaceAll(g.PathTemplate, "{namespace}", "{{.Namespace}}"), "{name}", "{{.Name}}")
	if _, err := template.New("path").Option("missingkey=error").Parse(parsed); err != nil {
		return fmt.Errorf("invalid path template: %w", err)
	}
	if g.Mode == GitDeliveryProposal && g.ProposalAdapter == nil && g.ProposalAdapterName == "" {
		return errors.New("proposal mode requires a proposal adapter")
	}
	if g.Mode != GitDeliveryDirect && g.Mode != GitDeliveryProposal {
		return errors.New("mode must be 'direct' or 'proposal'")
	}
	return nil
}

// PolicyStore holds roles, Git mappings, and configuration.
type PolicyStore struct {
	mu            sync.RWMutex
	CustomRoles   map[string]Role
	GitMappings   map[string]GitMapping // namespace -> GitMapping
	EnableDecrypt bool

	// groupRules are the group-to-role grants, each scoped to the namespaces it names,
	// ordered as the document listed them.
	groupRules []GroupRule
	// explicit records whether a policy document is in force, which is what turns off the
	// legacy fallback where an OIDC group named exactly after a role granted that role
	// everywhere: a deployment with a file must be able to revoke a grant by leaving it
	// out. Apply sets it; SetGroupRoles, which exists for tests, does not.
	explicit bool
}

func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		CustomRoles: make(map[string]Role),
		GitMappings: make(map[string]GitMapping),
	}
}

// NamespaceGrants returns the capabilities an identity's groups grant in every namespace,
// and the ones they grant only in the namespaces they name. A namespace absent from the
// scoped map has no grants of its own — which is a different thing from a namespace that is
// denied, since the global set still applies there.
func (s *PolicyStore) NamespaceGrants(groups []string) ([]Capability, map[string][]Capability) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	members := make(map[string]bool, len(groups))
	for _, group := range groups {
		members[group] = true
	}

	global := make(map[Capability]bool)
	scoped := make(map[string]map[Capability]bool)

	if !s.explicit {
		for _, group := range groups {
			if role, ok := s.getRole(group); ok {
				addCapabilities(global, role.Capabilities)
			}
		}
	}
	for _, rule := range s.groupRules {
		if !members[rule.Name] {
			continue
		}
		role, ok := s.getRole(rule.Role)
		if !ok {
			continue // a rule left pointing at a role the document no longer declares
		}
		for _, namespace := range rule.Namespaces {
			if namespace == AnyNamespace {
				addCapabilities(global, role.Capabilities)
				continue
			}
			if scoped[namespace] == nil {
				scoped[namespace] = make(map[Capability]bool)
			}
			addCapabilities(scoped[namespace], role.Capabilities)
		}
	}

	result := make(map[string][]Capability, len(scoped))
	for namespace, caps := range scoped {
		result[namespace] = orderedCapabilities(caps)
	}
	return orderedCapabilities(global), result
}

// CapabilitiesForGroups returns every capability the identity holds somewhere, whichever
// namespace grants it: the pre-filter for a request whose namespace is not known yet. It
// must not authorize a specific namespace — that is what NamespaceGrants is for.
func (s *PolicyStore) CapabilitiesForGroups(groups []string) []Capability {
	global, scoped := s.NamespaceGrants(groups)
	seen := make(map[Capability]bool, len(global))
	addCapabilities(seen, global)
	for _, caps := range scoped {
		addCapabilities(seen, caps)
	}
	return orderedCapabilities(seen)
}

func addCapabilities(seen map[Capability]bool, caps []Capability) {
	for _, capability := range caps {
		seen[capability] = true
	}
}

// orderedCapabilities renders a capability set in the canonical order of All,
// so two resolutions of the same grants produce the same list.
func orderedCapabilities(seen map[Capability]bool) []Capability {
	result := make([]Capability, 0, len(seen))
	for _, capability := range All {
		if seen[capability] {
			result = append(result, capability)
		}
	}
	return result
}

func (s *PolicyStore) AddCustomRole(role Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if IsBuiltInRole(role.Name) {
		return fmt.Errorf("role name %q conflicts with built-in role", role.Name)
	}
	if _, exists := s.CustomRoles[role.Name]; exists {
		return fmt.Errorf("custom role %q already exists", role.Name)
	}
	s.CustomRoles[role.Name] = role
	return nil
}

func (s *PolicyStore) GetRole(name string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getRole(name)
}

func (s *PolicyStore) getRole(name string) (Role, bool) {
	if role, ok := GetBuiltInRole(name); ok {
		return role, true
	}
	role, ok := s.CustomRoles[name]
	return role, ok
}

func (s *PolicyStore) SetGitMapping(mapping GitMapping) error {
	if err := mapping.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GitMappings[mapping.Namespace] = mapping
	return nil
}

// GetGitMapping returns the namespace's mapping, falling back to a configured "*" wildcard.
func (s *PolicyStore) GetGitMapping(namespace string) (GitMapping, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.GitMappings[namespace]; ok {
		return m, true
	}
	if m, ok := s.GitMappings["*"]; ok {
		res := m
		res.Namespace = namespace
		return res, true
	}
	return GitMapping{}, false
}

// SetGroupRoles atomically replaces a group's role mapping. The rules it writes apply in
// every namespace, which is the only thing an unnamespaced group-to-role mapping can mean;
// a namespaced grant comes from a policy document through Apply.
func (s *PolicyStore) SetGroupRoles(group string, roles []string) error {
	if strings.TrimSpace(group) == "" {
		return errors.New("group is required")
	}
	seen := make(map[string]bool, len(roles))
	s.mu.RLock()
	for _, name := range roles {
		if seen[name] {
			s.mu.RUnlock()
			return fmt.Errorf("duplicate role %q", name)
		}
		seen[name] = true
		if _, ok := s.getRole(name); !ok {
			s.mu.RUnlock()
			return fmt.Errorf("unknown role %q", name)
		}
	}
	s.mu.RUnlock()

	replacement := make([]GroupRule, 0, len(roles))
	for _, role := range roles {
		replacement = append(replacement, GroupRule{Name: group, Namespaces: []string{AnyNamespace}, Role: role})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// A fresh slice rather than a compaction in place: a reader that took the slice under
	// RLock must never observe this write through the array it is still walking.
	next := make([]GroupRule, 0, len(s.groupRules)+len(replacement))
	for _, existing := range s.groupRules {
		if existing.Name != group {
			next = append(next, existing)
		}
	}
	s.groupRules = append(next, replacement...)
	return nil
}

// ConfigureGitMappings atomically replaces all mappings after validating them.
func (s *PolicyStore) ConfigureGitMappings(mappings []GitMapping) error {
	next := make(map[string]GitMapping, len(mappings))
	for _, mapping := range mappings {
		if err := mapping.Validate(); err != nil {
			return err
		}
		if _, exists := next[mapping.Namespace]; exists {
			return fmt.Errorf("duplicate mapping for namespace %q", mapping.Namespace)
		}
		next[mapping.Namespace] = mapping
	}
	s.mu.Lock()
	s.GitMappings = next
	s.mu.Unlock()
	return nil
}

func (s *PolicyStore) GetAllMappings() map[string]GitMapping {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]GitMapping, len(s.GitMappings))
	for k, v := range s.GitMappings {
		result[k] = v
	}
	return result
}

// GitMappingSpec is the values-driven mapping definition: GitMapping with the proposal
// adapter referenced by registry name instead of by instance, so configuration carries no
// code.
type GitMappingSpec struct {
	Namespace           string
	Repository          string
	Branch              string
	PathTemplate        string
	AuthRef             string
	Mode                GitDeliveryMode
	ProposalAdapterName string
	// AllowedPaths optionally lists directory prefixes users may target; empty means only
	// the rendered PathTemplate is allowed.
	AllowedPaths []string
}

// SeedGitMappings atomically replaces all mappings from specs, resolving each proposal-mode
// adapter from the registry: an unknown name is a configuration error, never a nil adapter.
func (s *PolicyStore) SeedGitMappings(specs []GitMappingSpec, adapters map[string]gitops.ProposalProvider) error {
	mappings := make([]GitMapping, 0, len(specs))
	for _, spec := range specs {
		mapping := GitMapping{
			Namespace:           spec.Namespace,
			Repository:          spec.Repository,
			Branch:              spec.Branch,
			PathTemplate:        spec.PathTemplate,
			AuthRef:             spec.AuthRef,
			Mode:                spec.Mode,
			ProposalAdapterName: spec.ProposalAdapterName,
			AllowedPaths:        spec.AllowedPaths,
		}
		if spec.Mode == GitDeliveryProposal {
			adapter, ok := adapters[spec.ProposalAdapterName]
			if !ok {
				return fmt.Errorf("namespace %q: unknown proposal adapter %q", spec.Namespace, spec.ProposalAdapterName)
			}
			mapping.ProposalAdapter = adapter
		}
		mappings = append(mappings, mapping)
	}
	return s.ConfigureGitMappings(mappings)
}

// ResolveGitMapping fails closed when a namespace is not configured.
func (s *PolicyStore) ResolveGitMapping(namespace string) (GitMapping, error) {
	m, ok := s.GetGitMapping(namespace)
	if !ok {
		return GitMapping{}, fmt.Errorf("no Git mapping for namespace %q", namespace)
	}
	return m, nil
}

func RequiredCapabilitiesForOperation(op string) []Capability {
	switch op {
	case "list_namespaces", "get_sealedsecret", "list_sealedsecrets":
		return []Capability{MetadataRead}
	case "encrypt":
		return []Capability{SecretSeal}
	case "decrypt":
		return []Capability{SecretDecrypt}
	case "reseal":
		return []Capability{SecretSeal, SecretDecrypt}
	case "gitops_dry_run", "gitops_propose":
		return []Capability{GitOpsPropose}
	case "gitops_push":
		return []Capability{GitOpsPush}
	case "manage_acl":
		return []Capability{AccessManage}
	default:
		return nil // Unknown operation = deny
	}
}

// CheckAuthorization checks if an identity has all required capabilities for an operation.
// Decrypt and reseal additionally require ENABLE_DECRYPT, which the handler enforces.
func CheckAuthorization(identity Identity, operation string) error {
	required := RequiredCapabilitiesForOperation(operation)
	if required == nil {
		return errors.New("unknown operation: " + operation)
	}
	for _, cap := range required {
		if !identity.Has(cap) {
			return fmt.Errorf("missing capability %q for operation %q", cap, operation)
		}
	}
	return nil
}

func GitOpsCapabilityRequired(mode GitDeliveryMode) Capability {
	switch mode {
	case GitDeliveryDirect:
		return GitOpsPush
	case GitDeliveryProposal:
		return GitOpsPropose
	default:
		return ""
	}
}

func (g GitMapping) RenderPath(namespace, name string) string {
	if !safePathComponent(namespace) || !safePathComponent(name) {
		return ""
	}
	path := strings.ReplaceAll(g.PathTemplate, "{namespace}", namespace)
	path = strings.ReplaceAll(path, "{name}", name)
	clean := pathpkg.Clean(path)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
		return ""
	}
	return clean
}

// IsPathAllowed reports whether targetPath may be written here. With AllowedPaths empty only
// the exact RenderPath for this namespace/name is allowed; otherwise the target must sit
// under one of the allowed directory prefixes.
func (g GitMapping) IsPathAllowed(targetPath, namespace, name string) bool {
	defaultPath := g.RenderPath(namespace, name)
	if defaultPath == "" {
		return false
	}
	if len(g.AllowedPaths) == 0 {
		return targetPath == defaultPath
	}
	for _, allowed := range g.AllowedPaths {
		// An allowed prefix may itself carry {namespace}.
		prefix := strings.ReplaceAll(allowed, "{namespace}", namespace)
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		if strings.HasPrefix(targetPath, prefix) {
			clean := pathpkg.Clean(targetPath)
			if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
				return false
			}
			return clean != "" && clean != "."
		}
	}
	return false
}

func safePathComponent(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, "/\\")
}
