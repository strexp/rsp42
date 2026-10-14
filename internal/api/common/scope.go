package common

import "context"

// Scope carries request-scoped audit attribution: who made the call and which
// tenant it belongs to. Handlers resolve these (from the mTLS peer certificate,
// the ES2+ functionRequesterIdentifier, or the ES12 caller OID) and write them
// into the scope; the audit middleware reads the same pointer after the handler
// returns.
type Scope struct {
	Actor    string
	TenantID string
}

type scopeKey struct{}

// WithScope attaches a mutable scope to ctx.
func WithScope(ctx context.Context, s *Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeFrom returns the request scope, or nil when none was installed.
func ScopeFrom(ctx context.Context) *Scope {
	if s, ok := ctx.Value(scopeKey{}).(*Scope); ok {
		return s
	}
	return nil
}

// SetActor records the caller identity in the request scope (no-op without one).
func SetActor(ctx context.Context, actor string) {
	if s := ScopeFrom(ctx); s != nil {
		s.Actor = actor
	}
}

// SetTenant records the tenant attribution in the request scope (no-op without
// one).
func SetTenant(ctx context.Context, tenant string) {
	if s := ScopeFrom(ctx); s != nil {
		s.TenantID = tenant
	}
}
