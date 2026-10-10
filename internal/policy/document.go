// The authorization half of the Git-managed policy document: one document carries both
// authorization and namespace Git mappings, but only the authz half is read here. A `git:`
// section is accepted and ignored rather than refused, so a document written to the
// published schema still loads.
//
// Unknown fields, capabilities, roles, and versions all fail validation rather than being
// ignored, which is why the decode below is strict and every rule has its own error message.

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const (
	// AnyNamespace is the wildcard a group rule uses to grant in every namespace. It is the
	// only pattern accepted: a prefix glob would make a rule's reach a question about a
	// matcher rather than a fact about the file, and the file is meant to be read.
	AnyNamespace = "*"

	// SupportedVersion is the only document version the loader reads. A different version is
	// a document written against a contract this binary does not implement, so it is refused
	// rather than best-effort parsed.
	SupportedVersion = 1

	// denyDefault is the only authorization default the loader can honour: `allow` would
	// mean granting capabilities to a caller who matched no rule, which nothing here
	// implements, so it is refused rather than accepted and silently ignored.
	denyDefault = "deny"
)

// Document is the parsed policy file.
type Document struct {
	Version int   `json:"version"`
	Authz   Authz `json:"authz"`
	// Git is the document's Git half, which this loader does not read. Decoding it as opaque
	// bytes keeps a full-schema document loadable while still rejecting a misspelled field
	// inside the half that is read.
	Git json.RawMessage `json:"git,omitempty"`
}

type Authz struct {
	Defaults Defaults            `json:"defaults"`
	Roles    map[string]RoleSpec `json:"roles"`
	Groups   []GroupRule         `json:"groups"`
}

// Defaults is the documented deny-by-default declaration. Both fields must be `deny` when
// present; an absent section means the same thing.
type Defaults struct {
	Unauthenticated string `json:"unauthenticated"`
	Authenticated   string `json:"authenticated"`
}

type RoleSpec struct {
	Capabilities []Capability `json:"capabilities"`
}

// GroupRule grants one role to one OIDC group, in the namespaces it names. Several rules may
// name the same group with different namespace sets; their capabilities union.
type GroupRule struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
	Role       string   `json:"role"`
}

// ParseDocument decodes and validates a policy document, returning the first failure.
// Validate reports every failure at once, and is what a caller who wants the whole list
// should use.
func ParseDocument(data []byte) (Document, error) {
	if err := checkSingleDocument(data); err != nil {
		return Document{}, err
	}
	jsonBytes, err := yaml.YAMLToJSON(data)
	if err != nil {
		return Document{}, fmt.Errorf("policy document is not valid YAML: %w", err)
	}
	var doc Document
	decoder := json.NewDecoder(bytes.NewReader(jsonBytes))
	// Strict: the schema's contract is that unknown fields fail validation, and without this
	// a misspelled key would parse as a section that grants nothing — a rule that silently
	// does not apply.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("policy document: %w", err)
	}
	if decoder.More() {
		return Document{}, errors.New("policy document: trailing content after the first document")
	}
	if err := doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// checkSingleDocument rejects a file holding more than one YAML document: the decoder reads
// the first and ignores the rest, so a stray separator would turn an appended second policy
// into a silent no-op. The check is textual because no scalar in a policy document spans
// lines, so a `---` line is always a separator.
func checkSingleDocument(data []byte) error {
	seenContent, seenSeparator := false, false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" {
			if seenContent || seenSeparator {
				return errors.New("policy document: the file must hold exactly one document")
			}
			seenSeparator = true
			continue
		}
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			seenContent = true
		}
	}
	return nil
}

// Validate reports every problem in the document at once, so one pass over a broken file
// tells an operator everything that has to change.
func (d Document) Validate() error {
	var errs []error

	if d.Version != SupportedVersion {
		errs = append(errs, fmt.Errorf("version: must be %d, got %d", SupportedVersion, d.Version))
	}

	for _, def := range []struct{ field, value string }{
		{"authz.defaults.unauthenticated", d.Authz.Defaults.Unauthenticated},
		{"authz.defaults.authenticated", d.Authz.Defaults.Authenticated},
	} {
		if def.value != "" && def.value != denyDefault {
			errs = append(errs, fmt.Errorf("%s: only %q is supported, got %q", def.field, denyDefault, def.value))
		}
	}

	// Declared roles, in a stable order so the error list does not shuffle between runs of
	// the same file.
	declared := make(map[string]bool, len(d.Authz.Roles))
	for _, name := range sortedKeys(d.Authz.Roles) {
		if err := validateRole(name, d.Authz.Roles[name]); err != nil {
			errs = append(errs, err)
			continue
		}
		declared[name] = true
	}

	// One rule per group per namespace set: two rules for the same group over the same
	// namespaces contradict each other, and unioning them would answer the contradiction by
	// granting both — so it is refused.
	ruleIndex := make(map[string]int, len(d.Authz.Groups))
	for i, rule := range d.Authz.Groups {
		where := fmt.Sprintf("authz.groups[%d]", i)
		if rule.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", where))
			continue
		}
		if rule.Role == "" {
			errs = append(errs, fmt.Errorf("%s: group %q has no role", where, rule.Name))
			continue
		}
		if !IsBuiltInRole(rule.Role) && !declared[rule.Role] {
			errs = append(errs, fmt.Errorf("%s: group %q references unknown role %q", where, rule.Name, rule.Role))
		}
		if len(rule.Namespaces) == 0 {
			errs = append(errs, fmt.Errorf("%s: group %q grants in no namespace; list %q or an exact namespace name", where, rule.Name, AnyNamespace))
			continue
		}
		for _, namespace := range rule.Namespaces {
			if err := validateNamespacePattern(namespace); err != nil {
				errs = append(errs, fmt.Errorf("%s: group %q: %w", where, rule.Name, err))
			}
		}
		key := rule.Name + "\x00" + strings.Join(sortedUnique(rule.Namespaces), ",")
		if previous, duplicate := ruleIndex[key]; duplicate {
			errs = append(errs, fmt.Errorf("%s: group %q already has a rule for %s at authz.groups[%d]",
				where, rule.Name, strings.Join(sortedUnique(rule.Namespaces), ", "), previous))
			continue
		}
		ruleIndex[key] = i
	}

	return errors.Join(errs...)
}

// validateRole checks one declared role. A built-in may be redeclared only with exactly its
// canonical bundle: redefining one would let a ConfigMap quietly change what `platform-admin`
// means.
func validateRole(name string, spec RoleSpec) error {
	if name == "" {
		return errors.New("authz.roles: a role name is required")
	}
	if name == AnyNamespace || strings.ContainsAny(name, " \t") {
		return fmt.Errorf("authz.roles.%s: a role name cannot be %q or contain whitespace", name, AnyNamespace)
	}
	if len(spec.Capabilities) == 0 {
		return fmt.Errorf("authz.roles.%s: capabilities must list at least one capability", name)
	}
	if builtIn, ok := GetBuiltInRole(name); ok {
		if !sameCapabilitySet(builtIn.Capabilities, spec.Capabilities) {
			return fmt.Errorf("authz.roles.%s: built-in roles are immutable; expected %s, got %s",
				name, formatCapabilities(builtIn.Capabilities), formatCapabilities(spec.Capabilities))
		}
		return nil
	}
	if _, err := NewCustomRole(name, spec.Capabilities); err != nil {
		return fmt.Errorf("authz.roles.%s: %w", name, err)
	}
	return nil
}

// validateNamespacePattern accepts the wildcard or an exact namespace name, and refuses
// everything in between.
func validateNamespacePattern(namespace string) error {
	if namespace == AnyNamespace {
		return nil
	}
	if strings.Contains(namespace, AnyNamespace) {
		return fmt.Errorf("namespaces: %q is not supported; use %q or an exact namespace name", namespace, AnyNamespace)
	}
	if problems := validation.IsDNS1123Label(namespace); len(problems) > 0 {
		return fmt.Errorf("namespaces: %q is not a valid namespace name: %s", namespace, strings.Join(problems, "; "))
	}
	return nil
}

// Apply validates doc and, only if the whole document is valid, replaces the store's custom
// roles and group rules in one critical section; a document that fails validation leaves the
// store exactly as it was. Git mappings are untouched — the document's `git:` section is not
// read, so they keep arriving from GITOPS_NAMESPACES.
//
// Applying a document also switches the store off the legacy fallback: once a file is read,
// the file is the policy, and a grant it does not make does not exist.
func (s *PolicyStore) Apply(doc Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	roles := make(map[string]Role, len(doc.Authz.Roles))
	for name, spec := range doc.Authz.Roles {
		if IsBuiltInRole(name) {
			continue // built-ins resolve by name; nothing to store
		}
		role, err := NewCustomRole(name, spec.Capabilities)
		if err != nil {
			// Unreachable: Validate ran the same constructor over the same input. Returning
			// it keeps the failure honest if that changes.
			return fmt.Errorf("authz.roles.%s: %w", name, err)
		}
		roles[name] = role
	}
	rules := make([]GroupRule, len(doc.Authz.Groups))
	copy(rules, doc.Authz.Groups)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.CustomRoles = roles
	s.groupRules = rules
	s.explicit = true
	return nil
}

func sortedKeys(roles map[string]RoleSpec) []string {
	names := make([]string, 0, len(roles))
	for name := range roles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// sortedUnique dedupes and orders namespace names so two rules' namespace sets compare equal
// regardless of how they were written.
func sortedUnique(values []string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

// sameCapabilitySet compares two capability lists as sets, so a redeclared built-in is judged
// on what it grants rather than on how it was written.
func sameCapabilitySet(a, b []Capability) bool {
	left, right := map[Capability]bool{}, map[Capability]bool{}
	for _, c := range a {
		left[c] = true
	}
	for _, c := range b {
		right[c] = true
	}
	if len(left) != len(right) {
		return false
	}
	for c := range left {
		if !right[c] {
			return false
		}
	}
	return true
}

// formatCapabilities renders a capability list in the schema's own vocabulary for an error
// message, so the expected value can be pasted back into the file.
func formatCapabilities(caps []Capability) string {
	ordered := make([]string, 0, len(caps))
	seen := map[Capability]bool{}
	for _, known := range All {
		for _, c := range caps {
			if c == known && !seen[c] {
				seen[c] = true
				ordered = append(ordered, string(c))
			}
		}
	}
	return "[" + strings.Join(ordered, ", ") + "]"
}
