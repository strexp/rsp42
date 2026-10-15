package admin

import (
	"fmt"
	"strings"
	"time"

	"rsp42/internal/api/middleware"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// The management API declares the seams it uses, so the HTTP layer names the
// behaviour it needs rather than the SQLite repositories and concrete services
// (docs/architecture.md, "Dependency direction"). The concrete types satisfy
// these structurally, so the composition root needs no change, and the
// assertions below keep that true.
//
// The interfaces are grouped per resource aggregate.

// TenantStore is the tenant registry used by the tenant endpoints.
type TenantStore interface {
	Delete(id string) error
	DeleteWithReassign(id, reassignTo string) error
	Get(id string) (*store.Tenant, error)
	List() ([]*store.Tenant, error)
	Upsert(t *store.Tenant) error
	Usage(id string) (store.TenantUsage, error)
}

// ProfileStore is the profile inventory used by the profile endpoints.
type ProfileStore interface {
	Delete(iccid string) error
	GetByICCID(iccid string) (*store.Profile, error)
	ListEIDs(f store.ProfileFilter, limit, offset int) ([]store.EIDSummary, int, error)
	ListFiltered(f store.ProfileFilter, limit, offset int, sort string) ([]*store.Profile, int, error)
	Stats(f store.ProfileFilter, groupBy string) ([]store.StatCount, error)
	Update(p *store.Profile) error
}

// UPPStore is the SAIP template registry used by the template endpoints.
type UPPStore interface {
	CountForTenant(tenant string) (int, error)
	Delete(tenant, name string) error
	GetForTenant(tenant, name string) (*store.UPPTemplate, error)
	GetScoped(tenant, name string) (*store.UPPTemplate, error)
	GetVersion(tenant, name string, id int64) (*store.UPPTemplateVersion, error)
	List() ([]*store.UPPTemplate, error)
	ListForTenant(tenant string) ([]*store.UPPTemplate, error)
	ListVersions(tenant, name string) ([]*store.UPPTemplateVersion, error)
	SetActive(tenant, name string, active bool) error
	Upsert(t *store.UPPTemplate) error
	UpsertArchived(t *store.UPPTemplate, note string) error
}

// AuditStore is the audit log used by the audit endpoints and by the handler's
// own write auditing.
type AuditStore interface {
	Insert(e *store.AuditEntry) error
	ListAfterID(f store.AuditFilter, afterID int64, limit int) ([]*store.AuditEntry, error)
	ListBySubject(subject string, limit int) ([]*store.AuditEntry, error)
	ListFiltered(f store.AuditFilter, limit, offset int) ([]*store.AuditEntry, int, error)
	Stats(f store.AuditFilter, groupBy string) ([]store.StatCount, error)
}

// BatchStore is the download-batch registry.
type BatchStore interface {
	Delete(id int64) error
	Get(id int64) (*store.DownloadBatch, error)
	Insert(b *store.DownloadBatch) (int64, error)
	List(tenant string, limit, offset int) ([]*store.DownloadBatch, int, error)
	UpdateState(id int64, state string) error
}

// OrderStore is the per-profile order audit trail shown in the timeline.
type OrderStore interface {
	Insert(tenant, iccid, eid, matchingID, action, requestJSON, resultJSON string) error
	ListByICCID(iccid string) ([]*store.OrderRecord, error)
}

// NotificationStore is the received-notification log.
type NotificationStore interface {
	ListByICCID(iccid string) ([]*store.Notification, error)
	ListFiltered(f store.NotificationFilter, limit, offset int) ([]*store.Notification, int, error)
}

// SessionStore exposes the sessions attached to a profile.
type SessionStore interface {
	ListByProfileID(profileID int64) ([]*store.Session, error)
}

// PoolStore is the ICCID pool and its imported ranges.
type PoolStore interface {
	DeleteRange(id int64) (removed int, err error)
	ImportRange(tenant, start, end, note string) (rangeID int64, inserted, skipped int, err error)
	ListPage(state, prefix string, tenant *string, limit, offset int) ([]*store.ICCIDPoolEntry, int, error)
	ListRanges(tenant *string) ([]*store.ICCIDRange, error)
	Reserve(tenant, eid, reference string, ttl time.Duration) (string, error)
	SetState(iccid, state, note string) error
	Stats(tenant *string) (counts map[string]int, ranges int, err error)
}

// CallbackStore is the outbound ES2+ notification queue.
type CallbackStore interface {
	Get(id int64) (*store.Callback, error)
	ListFiltered(f store.CallbackFilter, limit, offset int) ([]*store.Callback, int, error)
	Requeue(id int64) error
	RequeueDead(tenant *string, before time.Time, limit int) (int64, error)
}

// OrderTransitions is the profile lifecycle state machine.
type OrderTransitions interface {
	Cancel(iccid string, unavailable bool) (*store.Profile, error)
	Confirm(iccid string, release bool) (*store.Profile, error)
	Delete(iccid string) error
	Release(iccid string) (*store.Profile, error)
}

// Allocator creates profile rows and reserves their ICCIDs.
type Allocator interface {
	Allocate(req service.AllocateRequest) (*store.Profile, error)
}

// PersonalizationStore is the per-ICCID personalization service.
type PersonalizationStore interface {
	CountUnbound(tenant string) (int, error)
	Delete(tenant, iccid string) error
	ListPage(iccidPrefix, tenant string, limit, offset int) ([]*personalization.Data, int, error)
	Put(tenant string, d *personalization.Data) error
	ReservePair(tenant, iccid string) (string, error)
	Resolve(tenant, iccid, imsi string) (*personalization.Data, error)
	UnbindPair(tenant, iccid string) error
}

// SAIPVersionChecker enforces profiles.allowed_saip_versions on template writes.
type SAIPVersionChecker interface {
	CheckSAIPVersion(major, minor int) *service.SAIPVersionRejection
}

// checkSAIPVersion applies the policy when one is configured. The policy is
// optional (a nil one means "no limit"), and a nil *service.SAIPVersionPolicy
// used to work only because its methods tolerated a nil receiver; through an
// interface that tolerance is gone, so the absence is handled here.
func checkSAIPVersion(policy SAIPVersionChecker, major, minor int) *service.SAIPVersionRejection {
	if policy == nil {
		return nil
	}
	return policy.CheckSAIPVersion(major, minor)
}

// Validate reports the seams that were not wired.
//
// The management API has no meaningful nil-dependency behaviour: some handlers
// answered 501, others dereferenced the field and panicked, which left callers
// unable to predict either. A missing store is a wiring bug, so the composition
// root calls this at startup and refuses to serve. Audit, Idem and AllowedSAIP
// are optional and deliberately not listed.
func (h *Handler) Validate() error {
	var missing []string
	for _, d := range []struct {
		name    string
		present bool
	}{
		{"Tenants", h.Tenants != nil},
		{"Profiles", h.Profiles != nil},
		{"Orders", h.Orders != nil},
		{"Inventory", h.Inventory != nil},
		{"UPP", h.UPP != nil},
		{"Perso", h.Perso != nil},
		{"Batch", h.Batch != nil},
		{"OrderRepo", h.OrderRepo != nil},
		{"Notifs", h.Notifs != nil},
		{"Sessions", h.Sessions != nil},
		{"Pool", h.Pool != nil},
		{"Callbacks", h.Callbacks != nil},
	} {
		if !d.present {
			missing = append(missing, d.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("admin: handler is missing dependencies: %s", strings.Join(missing, ", "))
	}
	return nil
}

// The concrete implementations must keep satisfying the seams.
var (
	_ TenantStore                 = (*store.TenantRepo)(nil)
	_ ProfileStore                = (*store.ProfileRepo)(nil)
	_ UPPStore                    = (*store.UPPRepo)(nil)
	_ AuditStore                  = (*store.AuditRepo)(nil)
	_ BatchStore                  = (*store.BatchRepo)(nil)
	_ OrderStore                  = (*store.OrderRepo)(nil)
	_ NotificationStore           = (*store.NotificationRepo)(nil)
	_ SessionStore                = (*store.SessionRepo)(nil)
	_ PoolStore                   = (*store.PoolRepo)(nil)
	_ CallbackStore               = (*store.CallbackRepo)(nil)
	_ middleware.IdempotencyStore = (*store.IdempotencyRepo)(nil)
	_ OrderTransitions            = (*service.OrderService)(nil)
	_ Allocator                   = (*service.Inventory)(nil)
	_ PersonalizationStore        = (*service.PersonalizationService)(nil)
	_ SAIPVersionChecker          = (*service.SAIPVersionPolicy)(nil)
)
