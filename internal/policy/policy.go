// Package policy implements the capability registry, role definitions,
// namespace Git mappings, and authorization logic for the kubeseal-ui API.
//
// Per internal-docs/engineering/backend/crypto-wrapper.md and phase-2.md:
//
// Capabilities:
//   - metadata:read   — list namespaces and SealedSecret metadata
//   - secret:seal     — encrypt / create SealedSecrets
//   - secret:decrypt  — decrypt (requires ENABLE_DECRYPT=true)
//   - gitops:propose  — propose sealed YAML via PR (GitOps proposal mode)
//   - gitops:push     — push sealed YAML directly to Git (GitOps direct mode)
//   - access:manage   — manage ACL mappings (platform admins)
//
// Built-in roles:
//   - viewer         — metadata:read
//   - editor         — metadata:read, secret:seal
//   - secret-manager — metadata:read, secret:seal, secret:decrypt
//   - platform-admin — metadata:read, secret:seal, access:manage (NO implicit decrypt or gitops)
//
// Custom roles are validated against known capabilities.
// Git mapping is per-namespace: namespace → {repo, branch, path template, auth ref, delivery mode}
package policy

import (
	"context"
	"errors"
	"fmt"
	pathpkg "path"
	"strings"
	"sync"
	"text/template"
)

// Capability is a named permission.
type Capability string

// Known capabilities.
const (
	MetadataRead  Capability = "metadata:read"
	SecretSeal    Capability = "secret:seal"
	SecretDecrypt Capability = "secret:decrypt"
	GitOpsPropose Capability = "gitops:propose"
	GitOpsPush    Capability = "gitops:push"
	AccessManage  Capability = "access:manage"
)

// All lists every capability for validation.
var All = []Capability{
	MetadataRead,
	SecretSeal,
	SecretDecrypt,
	GitOpsPropose,
	GitOpsPush,
	AccessManage,
}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	for _, known := range All {
		if c == known {
			return true
		}
	}
	return false
}

// Role is a named bundle of capabilities.
type Role struct {
	Name         string
	Capabilities []Capability
}

// Built-in roles per kubeseal-ui design.
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
		RolePlatformAdmin,
	}
)

// BuiltInRoleNames returns the names of all built-in roles.
func BuiltInRoleNames() []string {
	names := make([]string, len(BuiltInRoles))
	for i, r := range BuiltInRoles {
		names[i] = r.Name
	}
	return names
}

// IsBuiltInRole reports whether the name is a built-in role.
func IsBuiltInRole(name string) bool {
	for _, r := range BuiltInRoles {
		if r.Name == name {
			return true
		}
	}
	return false
}

// GetBuiltInRole returns a built-in role by name.
func GetBuiltInRole(name string) (Role, bool) {
	for _, r := range BuiltInRoles {
		if r.Name == name {
			return r, true
		}
	}
	return Role{}, false
}

// NewCustomRole creates a custom role with the given capabilities.
// Unknown capabilities are rejected.
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
	Roles    []string // Role names assigned to this identity
}

// Capabilities returns the additive union of capabilities from all roles.
func (i Identity) Capabilities() []Capability {
	seen := map[Capability]bool{}
	for _, roleName := range i.Roles {
		if role, ok := GetBuiltInRole(roleName); ok {
			for _, c := range role.Capabilities {
				seen[c] = true
			}
			continue
		}
		// Could also check custom roles from policy store
	}
	caps := make([]Capability, 0, len(seen))
	for c := range seen {
		caps = append(caps, c)
	}
	return caps
}

// Has reports whether the identity has the given capability.
func (i Identity) Has(c Capability) bool {
	for _, cap := range i.Capabilities() {
		if cap == c {
			return true
		}
	}
	return false
}

// GitDeliveryMode represents how sealed secrets are delivered to Git.
type GitDeliveryMode string

const (
	GitDeliveryDirect   GitDeliveryMode = "direct"   // Push directly to repo
	GitDeliveryProposal GitDeliveryMode = "proposal" // Create PR
)

// GitMapping defines the Git target for a namespace.
type GitMapping struct {
	Namespace       string
	Repository      string // e.g., "org/repo"
	Branch          string // e.g., "main"
	PathTemplate    string // e.g., "clusters/prod/{namespace}/{name}.yaml"
	AuthRef         string // Reference to auth secret/credentials
	Mode            GitDeliveryMode
	ProposalAdapter ProposalAdapter // required when Mode is proposal
}

// ProposalAdapter is the provider-specific proposal hook.
type ProposalAdapter interface {
	OpenProposal(context.Context, ProposalRequest) (ProposalResult, error)
}

type ProposalRequest struct{}
type ProposalResult struct{}

// Validate checks the GitMapping for required fields.
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
	if strings.Contains(g.PathTemplate, "{namespace}") == false || strings.Contains(g.PathTemplate, "{name}") == false {
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
	if g.Mode == GitDeliveryProposal && g.ProposalAdapter == nil {
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
	GroupRoles    map[string][]string
	EnableDecrypt bool
}

// NewPolicyStore creates a new policy store.
func NewPolicyStore() *PolicyStore {
	return &PolicyStore{
		CustomRoles: make(map[string]Role),
		GitMappings: make(map[string]GitMapping),
		GroupRoles:  make(map[string][]string),
	}
}

// CapabilitiesForGroups returns the additive capability union for group
// memberships. Unknown groups and roles contribute nothing, preserving deny-by-default.
func (s *PolicyStore) CapabilitiesForGroups(groups []string) []Capability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[Capability]bool)
	for _, group := range groups {
		for _, roleName := range s.GroupRoles[group] {
			role, ok := s.getRole(roleName)
			if !ok {
				continue
			}
			for _, cap := range role.Capabilities {
				seen[cap] = true
			}
		}
	}
	result := make([]Capability, 0, len(seen))
	for _, cap := range All {
		if seen[cap] {
			result = append(result, cap)
		}
	}
	return result
}

// AddCustomRole adds a custom role to the store.
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

// GetRole returns a role (built-in or custom) by name.
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

// SetGitMapping sets the Git mapping for a namespace.
func (s *PolicyStore) SetGitMapping(mapping GitMapping) error {
	if err := mapping.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GitMappings[mapping.Namespace] = mapping
	return nil
}

// GetGitMapping returns the Git mapping for a namespace.
func (s *PolicyStore) GetGitMapping(namespace string) (GitMapping, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.GitMappings[namespace]
	return m, ok
}

// SetGroupRoles atomically replaces a group's role mapping.
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
	s.mu.Lock()
	s.GroupRoles[group] = append([]string(nil), roles...)
	s.mu.Unlock()
	return nil
}

// ConfigureGitMappings atomically replaces all mappings after validation.
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

// ResolveGitMapping fails closed when a namespace is not configured.
func (s *PolicyStore) ResolveGitMapping(namespace string) (GitMapping, error) {
	m, ok := s.GetGitMapping(namespace)
	if !ok {
		return GitMapping{}, fmt.Errorf("no Git mapping for namespace %q", namespace)
	}
	return m, nil
}

// RequiredCapabilitiesForOperation returns the capabilities required for an operation.
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
	// Special check: decrypt/reseal require ENABLE_DECRYPT=true (validated by handler)
	return nil
}

// GitOpsCapabilityRequired returns the capability required for a GitOps mode.
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

// RenderPath renders the path template with namespace and name.
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

func safePathComponent(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, "/\\")
}
