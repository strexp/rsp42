package service

import (
	"fmt"
	"sort"
	"strings"

	"rsp42/internal/rsp"
)

// SAIPVersionPolicy is the set of SAIP versions the template registry accepts
// (profiles.allowed_saip_versions). It is the single choke point for the
// version limit: the management API, the template clone/promote/restore paths
// and the CLI importer all go through it.
//
// The configuration value is a list rather than a scalar on purpose
// (docs/esim42-integration-gaps.md §8.1 decision 8): today it is equivalent to
// an upper bound, but admitting a second major family later needs no
// configuration-shape change and no migration.
type SAIPVersionPolicy struct {
	allowed []rsp.Version
}

// NewSAIPVersionPolicy parses the configured "<major>.<minor>" entries. An
// empty list means "no limit" and is what tooling without a configuration uses.
func NewSAIPVersionPolicy(allowed []string) (*SAIPVersionPolicy, error) {
	p := &SAIPVersionPolicy{}
	for i, raw := range allowed {
		v, err := rsp.ParseVersion(raw)
		if err != nil {
			return nil, fmt.Errorf("profiles.allowed_saip_versions[%d]: %w", i, err)
		}
		p.allowed = append(p.allowed, v)
	}
	sort.Slice(p.allowed, func(i, j int) bool { return p.allowed[i].Compare(p.allowed[j]) < 0 })
	return p, nil
}

// Max returns the highest configured version; ok is false when no limit is set.
func (p *SAIPVersionPolicy) Max() (rsp.Version, bool) {
	if p == nil || len(p.allowed) == 0 {
		return rsp.Version{}, false
	}
	return p.allowed[len(p.allowed)-1], true
}

// Allows reports whether a template version is acceptable. A version is allowed
// when it does not exceed any configured version. With the current single-entry
// list this is exactly an upper bound; a future list such as ["2.3","3.2"]
// admits both major families without any code change.
func (p *SAIPVersionPolicy) Allows(major, minor int) bool {
	if p == nil || len(p.allowed) == 0 {
		return true
	}
	v := rsp.Version{Major: major, Minor: minor}
	for _, a := range p.allowed {
		if v.Compare(a) <= 0 {
			return true
		}
	}
	return false
}

// AllowedString renders the configured versions for error messages.
func (p *SAIPVersionPolicy) AllowedString() string {
	if p == nil || len(p.allowed) == 0 {
		return "unlimited"
	}
	parts := make([]string, 0, len(p.allowed))
	for _, v := range p.allowed {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

// SAIPVersionRejection describes a template refused by the version policy.
// It carries the stabilized management-API error code and the details object
// (docs/esim42-integration-gaps.md §1bis N16).
type SAIPVersionRejection struct {
	TemplateVersion string
	MaxSupported    string
}

// Error implements error so callers that only log can use it directly.
func (r *SAIPVersionRejection) Error() string {
	return fmt.Sprintf("SAIP v%s is above the supported baseline %s (V2.3.1 is a document revision and is encoded as 2.3)",
		r.TemplateVersion, r.MaxSupported)
}

// CheckSAIPVersion returns a rejection when (major, minor) is above the policy,
// or nil when the template is acceptable.
func (p *SAIPVersionPolicy) CheckSAIPVersion(major, minor int) *SAIPVersionRejection {
	if p.Allows(major, minor) {
		return nil
	}
	max, _ := p.Max()
	return &SAIPVersionRejection{
		TemplateVersion: rsp.Version{Major: major, Minor: minor}.String(),
		MaxSupported:    max.String(),
	}
}
