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
	// Function overrides the audited function name. It is only needed where the
	// URL path does not identify the function: the ASN.1 binding (§6.6) carries
	// every function on the single /gsma/rsp2/asn1 path, so its handler names the
	// function it actually decoded.
	Function string
	// Detail carries machine-readable audit details contributed by the handler
	// (e.g. a tenant-attribution warning) on top of the middleware's own fields.
	Detail map[string]any
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

// SetFunction overrides the audited function name for a request whose path does
// not identify it (no-op without a scope).
func SetFunction(ctx context.Context, function string) {
	if s := ScopeFrom(ctx); s != nil {
		s.Function = function
	}
}

// AddDetail adds one machine-readable audit detail to the request scope
// (no-op without a scope).
func AddDetail(ctx context.Context, key string, value any) {
	s := ScopeFrom(ctx)
	if s == nil {
		return
	}
	if s.Detail == nil {
		s.Detail = map[string]any{}
	}
	s.Detail[key] = value
}
