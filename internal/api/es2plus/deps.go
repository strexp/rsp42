// Handler dependencies: the interfaces the handlers consume, the Deps set and

package es2plus

import (
	"log/slog"

	"rsp42/internal/api/middleware"
	"rsp42/internal/client/es12"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

type OrderAuditor interface {
	Insert(tenant, iccid, eid, matchingID, action, requestJSON, resultJSON string) error
}

// AuditWriter records protocol-level ES2+ failures (ES2+ answers HTTP 200 with a
// Failed status for some functions, so the audit middleware cannot see them).
type AuditWriter interface {
	Insert(e *store.AuditEntry) error
}

// UPPValidator checks that a "<tenant>/<template>" profileType resolves to a
// registered template. It is defined here so the handler does not depend on the
// concrete SQLite repository.
type UPPValidator interface {
	GetForTenant(tenant, name string) (*store.UPPTemplate, error)
}

// MetricCounter counts interface-level events. It is the subset of
// *metrics.Registry the ES2+ handler uses.
type MetricCounter interface {
	Inc(name string, labels map[string]string)
}

// Orders is the profile lifecycle state machine the order functions drive.
type Orders interface {
	Confirm(iccid string, release bool) (*store.Profile, error)
	Cancel(iccid string, unavailable bool) (*store.Profile, error)
	Release(iccid string) (*store.Profile, error)
}

// Inventory allocates an ICCID and creates the profile row behind DownloadOrder.
type Inventory interface {
	Allocate(req service.AllocateRequest) (*store.Profile, error)
}

// TenantResolver maps header.functionRequesterIdentifier to a tenant.
type TenantResolver interface {
	Resolve(requester string) (tenant string, mapped bool)
	Len() int
}

// Registrar registers and deletes the SM-DS event of an order.
type Registrar interface {
	Register(eid, eventID, smdsAddress string, meta es12.EventMeta) error
	DeleteForEID(eid string, meta es12.EventMeta) error
	DeleteEvent(eid, eventID string, meta es12.EventMeta) error
}

// Deps is the complete ES2+ handler dependency set, so the handler cannot be
// constructed half-wired. The two late-bound hooks stay out of it on purpose:
//
//   - Registrar registers SM-DS events and is installed once the ES12 client
//     exists (its construction needs the SM-DP+ identity, not this handler);
//   - ACRHandler serves the inbound handleAcrRequest stub and is unused by
//     rsp42 itself (ACR is performed outbound).
type Deps struct {
	Log       *slog.Logger
	Profiles  service.ProfileStore
	Orders    Orders
	Inventory Inventory
	// UPP validates a "<tenant>/<template>" profileType.
	UPP UPPValidator
	// RequesterTenants maps header.functionRequesterIdentifier to a tenant
	// (decision 3). A nil resolver means "everything is the platform default".
	RequesterTenants TenantResolver
	// Idem, when set, enables Idempotency-Key replay on the write functions
	// whose resend semantics SGP.22 does not define.
	Idem middleware.IdempotencyStore
	// OrderAudit, when set, records each order action.
	OrderAudit OrderAuditor
	// Metrics, when set, counts ES12 registration failures.
	Metrics MetricCounter
	// AuditRepo, when set, records ES12 registration failures.
	AuditRepo AuditWriter
}

// Handler serves the ES2+ interface.
type Handler struct {
	Deps
	// ACRHandler, when set, is invoked for handleAcrRequest.
	ACRHandler func(req AcrRequest) (*AcrResponse, error)
	// Registrar, when set, registers an SM-DS event on ConfirmOrder.
	Registrar Registrar
}

// New returns a new ES2+ handler with its dependencies wired.
func New(d Deps) *Handler { return &Handler{Deps: d} }

// The concrete services must keep satisfying the seams.
var (
	_ Orders         = (*service.OrderService)(nil)
	_ Inventory      = (*service.Inventory)(nil)
	_ TenantResolver = (*service.TenantResolver)(nil)
	_ Registrar      = (*service.Registrar)(nil)
)
