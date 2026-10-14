// Package admin implements the management API (BSS/OSS-facing) for the SM-DP+:
// tenants, profile inventory, UPP template registry and personalization. It is
// served on the admin listener under /admin/api/v1 and has no UI.
package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/common"
	"rsp42/internal/api/middleware"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// adminActor is the fixed audit actor for the (unauthenticated, internal)
// management API.
const adminActor = "esim42-backend"

// Handler holds the management API dependencies.
type Handler struct {
	Log       *slog.Logger
	Tenants   *store.TenantRepo
	Profiles  *store.ProfileRepo
	Orders    *service.OrderService
	Inventory *service.Inventory
	UPP       *store.UPPRepo
	Perso     *service.PersonalizationService
	Audit     *store.AuditRepo
	Batch     *store.BatchRepo
	OrderRepo *store.OrderRepo
	Notifs    *store.NotificationRepo
	Sessions  *store.SessionRepo
	Pool      *store.PoolRepo
	Events    *store.EventRepo
	// Callbacks exposes the outbound ES2+ notification queue (N2).
	Callbacks *store.CallbackRepo
	// Idem enables Idempotency-Key replay on the management writes.
	Idem *store.IdempotencyRepo
	// AllowedSAIP enforces profiles.allowed_saip_versions on every template
	// write (N16). A nil policy means "no limit".
	AllowedSAIP *service.SAIPVersionPolicy
	// DefaultReserveTTL bounds how long an unclaimed pool reservation may live.
	DefaultReserveTTL time.Duration
	// FQDN and OID are used when generating activation codes.
	FQDN string
	OID  string
}

// normalizeICCID strips a trailing F padding nibble.
func normalizeICCID(s string) string { return strings.TrimRight(s, "fF") }

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
			r.Post("/{iccid}/confirm", h.confirmProfile)
			r.Post("/{iccid}/cancel", h.cancelProfile)
			r.Post("/{iccid}/release", h.releaseProfile)
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

// Helpers -------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody(errCode(status, msg), msg))
}

// errorBody is the stable management-API error model (G10).
func errorBody(code, message string) map[string]string {
	return map[string]string{"code": code, "message": message}
}

// errorBodyDetails is errorBody plus a machine-readable details object. It is
// used where a stable code alone is not enough to act on (N16, N3).
func errorBodyDetails(code, message string, details any) map[string]any {
	body := map[string]any{"code": code, "message": message}
	if details != nil {
		body["details"] = details
	}
	return body
}

// writeSAIPVersionErr reports a template refused by profiles.allowed_saip_versions
// (N16). The stable code is saip_version_not_supported.
func (h *Handler) writeSAIPVersionErr(w http.ResponseWriter, rej *service.SAIPVersionRejection) {
	if rej == nil {
		return
	}
	writeJSON(w, http.StatusConflict, errorBodyDetails("saip_version_not_supported", rej.Error(),
		map[string]any{"templateVersion": rej.TemplateVersion, "maxSupported": rej.MaxSupported}))
}

// errCode derives a stable machine-readable code from the HTTP status when a
// handler has no more specific one. Every status a handler can produce maps to
// a named code; there is deliberately no bare "error" code (N7).
func errCode(status int, msg string) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "unprocessable_entity"
	case http.StatusNotImplemented:
		return "not_implemented"
	default:
		if status >= 500 {
			return "internal_error"
		}
		return "request_failed"
	}
}

// readJSON decodes a management-API request body. The size budget comes from
// middleware.MaxBody (api.Options.BodyLimit), so no separate limit applies.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// tenantFilter returns the `?tenant=` filter: nil when absent, a pointer to the
// raw value otherwise ("" selects the platform-default rows).
func tenantFilter(r *http.Request) *string {
	q := r.URL.Query()
	if !q.Has("tenant") {
		return nil
	}
	t := strings.TrimSpace(q.Get("tenant"))
	return &t
}

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
	actor, tenant := adminActor, ""
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
	writeJSON(w, http.StatusOK, openAPIDoc())
}

func op(summary string, params ...string) map[string]any {
	m := map[string]any{"summary": summary, "responses": map[string]any{"200": map[string]any{"description": "OK"}}}
	if len(params) > 0 && params[0] != "" {
		m["parameters"] = []map[string]string{{"name": "query", "in": "query", "description": params[0]}}
	}
	return m
}

// clampSize bounds a page size to [1, maxPageSize] with the shared default.
func clampSize(n int) int {
	if n < 1 {
		return defaultPageSize
	}
	if n > maxPageSize {
		return maxPageSize
	}
	return n
}

// clampPage bounds a 1-based page number.
func clampPage(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// parseID parses a positive identifier.
func parseID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid id %q", s)
	}
	return id, nil
}

// parseTime parses a query timestamp; nil when empty or unparsable.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

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

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// writeTenantErr reports a tenant-resolution failure with a stable code.
func writeTenantErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, errorBody("unknown_tenant", err.Error()))
}

// writeQuotaErr reports a quota violation with a stable code.
func writeQuotaErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusConflict, errorBody("quota_exceeded", err.Error()))
}
