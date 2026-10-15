// Package admin implements the management API (BSS/OSS-facing) for the SM-DP+:
// tenants, profile inventory, UPP template registry and personalization. It is
// served on the admin listener under /admin/api/v1 and has no UI.
package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/admin/openapi"
	"rsp42/internal/api/adminhttp"
	"rsp42/internal/api/common"
	"rsp42/internal/api/middleware"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// Handler holds the management API dependencies.
type Handler struct {
	Log       *slog.Logger
	Tenants   TenantStore
	Profiles  ProfileStore
	Orders    OrderTransitions
	Inventory Allocator
	UPP       UPPStore
	Perso     PersonalizationStore
	Audit     AuditStore
	Batch     BatchStore
	OrderRepo OrderStore
	Notifs    NotificationStore
	Sessions  SessionStore
	Pool      PoolStore
	// Callbacks exposes the outbound ES2+ notification queue (N2).
	Callbacks CallbackStore
	// Idem enables Idempotency-Key replay on the management writes.
	Idem middleware.IdempotencyStore
	// AllowedSAIP enforces profiles.allowed_saip_versions on every template
	// write (N16). A nil policy means "no limit".
	AllowedSAIP SAIPVersionChecker
	// DefaultReserveTTL bounds how long an unclaimed pool reservation may live.
	DefaultReserveTTL time.Duration
	// FQDN and OID are used when generating activation codes.
	FQDN string
	OID  string
}

// Mount registers the management API on r.
func Mount(r chi.Router, h *Handler) {
	idem := middleware.Idempotency(h.Idem)
	r.Route("/admin/api/v1", func(r chi.Router) {
		r.Get("/openapi.json", h.openapi)

		r.Route("/tenants", func(r chi.Router) {
			r.Get("/", h.listTenants)
			r.Post("/", h.upsertTenant)
			r.Get("/{id}", h.getTenant)
			r.Patch("/{id}", h.upsertTenant)
			r.Delete("/{id}", h.deleteTenant)
		})

		r.Route("/profiles", func(r chi.Router) {
			r.Get("/", h.listProfiles)
			r.With(idem).Post("/", h.createProfile)
			r.Post("/bulk", h.bulkProfiles)
			r.Get("/export", h.exportProfiles)
			r.With(idem).Post("/import", h.importProfiles)
			r.Get("/stats", h.profileStats)
			r.Get("/{iccid}", h.getProfile)
			r.Patch("/{iccid}", h.updateProfile)
			r.Delete("/{iccid}", h.deleteProfile)
			r.With(idem).Post("/{iccid}/confirm", h.confirmProfile)
			r.With(idem).Post("/{iccid}/cancel", h.cancelProfile)
			r.With(idem).Post("/{iccid}/release", h.releaseProfile)
			r.Post("/{iccid}/activation-code", h.activationCode)
			r.Get("/{iccid}/timeline", h.profileTimeline)
		})

		r.Route("/upp", func(r chi.Router) {
			r.Get("/", h.listUPP)
			r.Post("/", h.putUPP)
			r.Post("/validate", h.validateUPP)
			r.Post("/render", h.renderUPP)
			r.Get("/{name}", h.getUPP)
			r.Get("/{name}/bytes", h.getUPPBytes)
			r.Get("/{name}/decoded", h.decodedUPP)
			r.Get("/{name}/schema", h.uppSchema)
			r.Delete("/{name}", h.deleteUPP)
			r.Post("/{name}/activate", h.activateUPP)
			r.Post("/{name}/deactivate", h.deactivateUPP)
			r.Post("/{name}/clone", h.cloneUPP)
			r.Post("/{name}/promote", h.promoteUPP)
			r.Get("/{name}/versions", h.listUPPVersions)
			r.Post("/{name}/versions/{version}/restore", h.restoreUPP)
		})

		r.Route("/batches", func(r chi.Router) {
			r.Get("/", h.listBatches)
			r.With(idem).Post("/", h.createBatch)
			r.Get("/{id}", h.getBatch)
			r.Get("/{id}/items", h.listBatchItems)
			r.Post("/{id}/confirm", h.confirmBatch)
			r.Post("/{id}/cancel", h.cancelBatch)
			r.Delete("/{id}", h.deleteBatch)
		})

		r.Get("/eids", h.listEIDs)

		r.Route("/callbacks", func(r chi.Router) {
			r.Get("/", h.listCallbacks)
			r.Post("/retry-dead", h.retryDeadCallbacks)
			r.Post("/{id}/retry", h.retryCallback)
		})

		r.Get("/audit", h.listAudit)
		r.Get("/audit/stats", h.auditStats)
		r.Get("/notifications", h.listNotifications)

		r.Route("/iccid-pool", func(r chi.Router) {
			r.Get("/", h.listPool)
			r.Get("/stats", h.poolStats)
			r.Post("/reserve", h.reserveICCID)
			r.Post("/release", h.releaseICCID)
			r.Post("/block", h.blockICCID)
		})
		r.Route("/iccid-ranges", func(r chi.Router) {
			r.Get("/", h.listRanges)
			r.Post("/", h.importRange)
			r.Delete("/{id}", h.deleteRange)
		})

		r.Route("/personalization", func(r chi.Router) {
			r.Get("/", h.listPerso)
			r.Get("/export", h.exportPersonalization)
			r.Post("/import", h.importPerso)
			r.Post("/pool/import", h.importPersoPool)
			r.Get("/{iccid}", h.getPerso)
			r.Put("/{iccid}", h.putPerso)
			r.Delete("/{iccid}", h.deletePerso)
		})
	})
}

// adminhttp.ErrorBody is the stable management-API error model (G10).

// adminhttp.ErrorBodyDetails is adminhttp.ErrorBody plus a machine-readable details object. It is
// used where a stable code alone is not enough to act on (N16, N3).

// writeSAIPVersionErr reports a template refused by profiles.allowed_saip_versions
// (N16). The stable code is saip_version_not_supported.
func (h *Handler) writeSAIPVersionErr(w http.ResponseWriter, rej *service.SAIPVersionRejection) {
	if rej == nil {
		return
	}
	adminhttp.WriteJSON(w, http.StatusConflict, adminhttp.ErrorBodyDetails("saip_version_not_supported", rej.Error(),
		map[string]any{"templateVersion": rej.TemplateVersion, "maxSupported": rej.MaxSupported}))
}

// adminhttp.ErrCode derives a stable machine-readable code from the HTTP status when a
// handler has no more specific one. Every status a handler can produce maps to
// a named code; there is deliberately no bare "error" code (N7).

// adminhttp.ReadJSON decodes a management-API request body. The size budget comes from
// middleware.MaxBody (api.Options.BodyLimit), so no separate limit applies.

// adminhttp.TenantFilter returns the `?tenant=` filter: nil when absent, a pointer to the
// raw value otherwise ("" selects the platform-default rows).

// effectiveTenant resolves the tenant of a write: the explicit body value wins,
// then `?tenant=`. A non-empty tenant must be registered. The resolved value is
// recorded in the audit scope.
func (h *Handler) effectiveTenant(r *http.Request, explicit string) (string, error) {
	tenant := strings.TrimSpace(explicit)
	if tenant == "" {
		tenant = strings.TrimSpace(r.URL.Query().Get("tenant"))
	}
	if tenant != "" && h.Tenants != nil {
		if _, err := h.Tenants.Get(tenant); err != nil {
			return "", fmt.Errorf("unknown tenant %q", tenant)
		}
	}
	common.SetTenant(r.Context(), tenant)
	return tenant, nil
}

// audit records a management-API action. The tenant comes from the request
// scope (set by effectiveTenant) and the actor is the fixed internal backend
// identity.
func (h *Handler) audit(r *http.Request, fn, subject, outcome string, detail any) {
	if h.Audit == nil {
		return
	}
	dj := ""
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			dj = string(b)
		}
	}
	actor, tenant := adminhttp.Actor, ""
	if s := common.ScopeFrom(r.Context()); s != nil {
		if s.Actor != "" {
			actor = s.Actor
		}
		tenant = s.TenantID
	}
	if id := r.Header.Get("X-Request-ID"); id != "" {
		var m map[string]any
		if dj != "" {
			_ = json.Unmarshal([]byte(dj), &m)
		}
		if m == nil {
			m = map[string]any{}
		}
		m["requestId"] = id
		if b, err := json.Marshal(m); err == nil {
			dj = string(b)
		}
	}
	_ = h.Audit.Insert(&store.AuditEntry{
		TenantID: tenant, Actor: actor,
		Interface: "admin", Function: fn, Subject: subject, Outcome: outcome,
		RemoteAddr: r.RemoteAddr, DetailJSON: dj,
	})
}

// recordOrder appends an order-audit row so admin-driven order actions show up
// in the per-profile timeline (the ES2+ path records into the same table).
func (h *Handler) recordOrder(tenant, iccid, eid, matchingID, action string, req any) {
	if h.OrderRepo == nil {
		return
	}
	b, _ := json.Marshal(req)
	_ = h.OrderRepo.Insert(tenant, iccid, eid, matchingID, action, string(b), "")
}

// openapi returns the complete OpenAPI 3.0 description of the management API.
func (h *Handler) openapi(w http.ResponseWriter, _ *http.Request) {
	adminhttp.WriteJSON(w, http.StatusOK, openapi.Doc())
}

// adminhttp.ClampSize bounds a page size to [1, adminhttp.MaxPageSize] with the shared default.

// adminhttp.ClampPage bounds a 1-based page number.

// adminhttp.ParseID parses a positive identifier.

// adminhttp.ParseTime parses a query timestamp; nil when empty or unparsable.

// serviceAllocate maps a create-profile request onto an allocation request.
func serviceAllocate(req createProfileReq, tenant string) service.AllocateRequest {
	return service.AllocateRequest{
		EID:         req.EID,
		ProfileType: req.ProfileType,
		ICCID:       req.ICCID,
		UPPTemplate: req.UPPTemplate,
		Tenant:      tenant,
		ExternalRef: req.ExternalRef,
	}
}

// adminhttp.FirstNonEmpty returns the first non-empty string.

// writeTenantErr reports a tenant-resolution failure with a stable code.
func writeTenantErr(w http.ResponseWriter, err error) {
	adminhttp.WriteJSON(w, http.StatusBadRequest, adminhttp.ErrorBody("unknown_tenant", err.Error()))
}

// writeQuotaErr reports a quota violation with a stable code.
func writeQuotaErr(w http.ResponseWriter, err error) {
	adminhttp.WriteJSON(w, http.StatusConflict, adminhttp.ErrorBody("quota_exceeded", err.Error()))
}
