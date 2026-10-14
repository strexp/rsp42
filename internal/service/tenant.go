package service

// RequesterTenant maps a self-declared ES2+ header.functionRequesterIdentifier
// to a tenant id (see docs/esim42-integration-gaps.md §8.1 decision 3).
type RequesterTenant struct {
	Requester string
	Tenant    string
}

// TenantResolver resolves a caller-declared requester identifier to a tenant.
// The identifier is self-declared (SGP.22 §6.5.1.3 imposes no format), so the
// mapping is a trust decision made by the deployment: it is only sound when the
// ES2+ listener is reachable exclusively by the operator system that owns the
// mapping.
type TenantResolver struct {
	byRequester map[string]string
}

// NewTenantResolver builds a resolver from requester->tenant pairs.
func NewTenantResolver(pairs []RequesterTenant) *TenantResolver {
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		if p.Requester == "" {
			continue
		}
		m[p.Requester] = p.Tenant
	}
	return &TenantResolver{byRequester: m}
}

// Resolve returns the tenant for a requester identifier. mapped is false when
// no mapping exists (the caller then falls back to the platform default).
func (r *TenantResolver) Resolve(requester string) (tenant string, mapped bool) {
	if r == nil || requester == "" {
		return "", false
	}
	t, ok := r.byRequester[requester]
	return t, ok
}

// Len reports how many mappings are configured.
func (r *TenantResolver) Len() int {
	if r == nil {
		return 0
	}
	return len(r.byRequester)
}

// TenantLookup resolves tenant-scoped defaults.
type TenantLookup interface {
	DefaultUPPForTenant(tenant string) (string, error)
	CallbackURLForTenant(tenant string) (string, error)
}
