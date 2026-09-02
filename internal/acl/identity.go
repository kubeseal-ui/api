package acl

import (
	"sort"
)

// identity is a deterministic Identity implementation.
type identity struct {
	id     string
	groups []string
	caps   map[Capability]bool
}

// NewIdentity builds an Identity with an explicit capability set.
// Capabilities are validated; unknown ones are rejected.
func NewIdentity(id string, groups []string, caps []Capability) (Identity, error) {
	set := map[Capability]bool{}
	for _, c := range caps {
		if !c.Valid() {
			return nil, &UnknownCapabilityError{Capability: c, Role: "identity"}
		}
		set[c] = true
	}
	return &identity{id: id, groups: groups, caps: set}, nil
}

// capOrder returns caps in the canonical All declaration order.
func capOrder(caps []Capability) []Capability {
	rank := make(map[Capability]int, len(All))
	for i, c := range All {
		rank[c] = i
	}
	out := make([]Capability, len(caps))
	copy(out, caps)
	sort.Slice(out, func(i, j int) bool { return rank[out[i]] < rank[out[j]] })
	return out
}

// IdentityFromRoles builds an Identity whose capabilities are the
// additive union of the given roles' capabilities. An identity in
// multiple groups gets every capability of every role — union, not
// intersection or last-wins.
func IdentityFromRoles(id string, groups []string, roles ...Role) (Identity, error) {
	set := map[Capability]bool{}
	for _, r := range roles {
		for _, c := range r.Capabilities() {
			set[c] = true
		}
	}
	caps := make([]Capability, 0, len(set))
	for c := range set {
		caps = append(caps, c)
	}
	return NewIdentity(id, groups, capOrder(caps))
}

// ID implements Identity.
func (i *identity) ID() string { return i.id }

// Groups implements Identity.
func (i *identity) Groups() []string {
	out := make([]string, len(i.groups))
	copy(out, i.groups)
	return out
}

// Has implements Identity.
func (i *identity) Has(c Capability) bool { return i.caps[c] }

// Capabilities implements Identity.
func (i *identity) Capabilities() []Capability {
	out := make([]Capability, 0, len(i.caps))
	for c := range i.caps {
		out = append(out, c)
	}
	return capOrder(out)
}
