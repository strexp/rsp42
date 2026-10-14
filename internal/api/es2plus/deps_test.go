package es2plus_test

import (
	"rsp42/internal/api/es2plus"
	"rsp42/internal/api/middleware"
	"rsp42/internal/metrics"
	"rsp42/internal/store"
)

// The ES2+ handler depends on consumer-defined interfaces; the concrete
// implementations must satisfy them, which is what keeps the composition root
// free to keep passing the repositories it already builds.
var (
	_ es2plus.UPPValidator        = (*store.UPPRepo)(nil)
	_ es2plus.AuditWriter         = (*store.AuditRepo)(nil)
	_ middleware.IdempotencyStore = (*store.IdempotencyRepo)(nil)
	_ es2plus.MetricCounter       = (*metrics.Registry)(nil)
)
