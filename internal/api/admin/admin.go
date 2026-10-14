// Package admin implements the management API (BSS/OSS-facing) for the SM-DP+:
// profile inventory, UPP template registry and personalization. It is served on
// the admin listener under /admin/api/v1 and has no UI.
package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/service"
	"rsp42/internal/store"
)

const maxBody = 8 << 20

// Handler holds the management API dependencies.
type Handler struct {
	Log       *slog.Logger
	Profiles  *store.ProfileRepo
	Orders    *service.OrderService
	Inventory *service.Inventory
	UPP       *store.UPPRepo
	Perso     *service.PersonalizationService
	Audit     *store.AuditRepo
	Batch     *store.BatchRepo
	OrderRepo *store.OrderRepo
	Notifs    *store.NotificationRepo
	Pool      *store.PoolRepo
	// FQDN and OID are used when generating activation codes.
	FQDN string
	OID  string
}

// normalizeICCID strips a trailing F padding nibble.
func normalizeICCID(s string) string { return strings.TrimRight(s, "fF") }

// Mount registers the management API on r.
func Mount(r chi.Router, h *Handler) {
	r.Route("/admin/api/v1", func(r chi.Router) {
		r.Get("/openapi.json", h.openapi)

		r.Route("/profiles", func(r chi.Router) {
			r.Get("/", h.listProfiles)
			r.Post("/", h.createProfile)
			r.Post("/bulk", h.bulkProfiles)
			r.Get("/export", h.exportProfiles)
			r.Post("/import", h.importProfiles)
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
			r.Get("/{name}", h.getUPP)
			r.Get("/{name}/bytes", h.getUPPBytes)
			r.Get("/{name}/decoded", h.decodedUPP)
			r.Delete("/{name}", h.deleteUPP)
			r.Post("/{name}/activate", h.activateUPP)
			r.Post("/{name}/deactivate", h.deactivateUPP)
		})

		r.Route("/batches", func(r chi.Router) {
			r.Get("/", h.listBatches)
			r.Post("/", h.createBatch)
			r.Get("/{id}", h.getBatch)
			r.Get("/{id}/items", h.listBatchItems)
			r.Post("/{id}/confirm", h.confirmBatch)
			r.Post("/{id}/cancel", h.cancelBatch)
			r.Delete("/{id}", h.deleteBatch)
		})

		r.Get("/audit", h.listAudit)

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
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(v); err != nil {
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
	_ = h.Audit.Insert(&store.AuditEntry{
		Interface: "admin", Function: fn, Subject: subject, Outcome: outcome,
		RemoteAddr: r.RemoteAddr, DetailJSON: dj,
	})
}

// recordOrder appends an order-audit row so admin-driven order actions show up
// in the per-profile timeline (the ES2+ path records into the same table).
func (h *Handler) recordOrder(iccid, eid, matchingID, action string, req any) {
	if h.OrderRepo == nil {
		return
	}
	b, _ := json.Marshal(req)
	_ = h.OrderRepo.Insert(iccid, eid, matchingID, action, string(b), "")
}

// openapi returns a compact description of the management API.
func (h *Handler) openapi(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, openAPIDoc)
}

var openAPIDoc = map[string]any{
	"openapi": "3.0.3",
	"info": map[string]any{
		"title":   "rsp42 management API",
		"version": "0.1.0",
		"description": "BSS/OSS-facing management API for the SM-DP+. Profiles, UPP " +
			"template registry and per-ICCID personalization. No authentication " +
			"(deploy behind a trusted network).",
	},
	"paths": map[string]any{
		"/admin/api/v1/profiles": map[string]any{
			"get":  op("List profiles", "state, eid, iccid, q, page, size, sort"),
			"post": op("Create a profile (downloadOrder)"),
		},
		"/admin/api/v1/profiles/{iccid}": map[string]any{
			"get":    op("Get a profile"),
			"patch":  op("Update mutable profile fields"),
			"delete": op("Delete a profile"),
		},
		"/admin/api/v1/profiles/{iccid}/timeline":        map[string]any{"get": op("Merged order + notification timeline for a profile")},
		"/admin/api/v1/profiles/{iccid}/confirm":         map[string]any{"post": op("Confirm the download order")},
		"/admin/api/v1/profiles/{iccid}/cancel":          map[string]any{"post": op("Cancel the download order")},
		"/admin/api/v1/profiles/{iccid}/release":         map[string]any{"post": op("Release the profile")},
		"/admin/api/v1/profiles/{iccid}/activation-code": map[string]any{"post": op("Generate an activation code")},
		"/admin/api/v1/profiles/bulk":                    map[string]any{"post": op("Apply an action (confirm|cancel|release|delete) to a list of ICCIDs")},
		"/admin/api/v1/profiles/export":                  map[string]any{"get": op("Export profiles (format=csv|json, same filters as the list)")},
		"/admin/api/v1/profiles/import":                  map[string]any{"post": op("Import profiles from a JSON record list")},
		"/admin/api/v1/batches":                          map[string]any{"get": op("List download batches"), "post": op("Create a download batch (allocates N profiles)")},
		"/admin/api/v1/batches/{id}":                     map[string]any{"get": op("Get a batch and its state breakdown"), "delete": op("Delete a batch")},
		"/admin/api/v1/batches/{id}/items":               map[string]any{"get": op("List the profiles in a batch")},
		"/admin/api/v1/batches/{id}/confirm":             map[string]any{"post": op("Confirm all profiles in a batch")},
		"/admin/api/v1/batches/{id}/cancel":              map[string]any{"post": op("Cancel all profiles in a batch")},
		"/admin/api/v1/upp":                              map[string]any{"get": op("List UPP templates"), "post": op("Add/replace a UPP template (base64 DER, SAIP version parsed server-side)")},
		"/admin/api/v1/upp/{name}":                       map[string]any{"get": op("Get UPP metadata"), "delete": op("Delete a UPP template")},
		"/admin/api/v1/upp/{name}/bytes":                 map[string]any{"get": op("Download the UPP DER")},
		"/admin/api/v1/upp/{name}/decoded":               map[string]any{"get": op("Decoded UPP view (header, services, GFSTE, elements, files)")},
		"/admin/api/v1/upp/{name}/activate":              map[string]any{"post": op("Enable a UPP template")},
		"/admin/api/v1/upp/{name}/deactivate":            map[string]any{"post": op("Disable a UPP template")},
		"/admin/api/v1/audit":                            map[string]any{"get": op("Query the audit log", "interface, function, subject, actor, outcome, since, until, page, size")},
		"/admin/api/v1/iccid-pool":                       map[string]any{"get": op("List ICCID pool entries", "state, iccid, page, size")},
		"/admin/api/v1/iccid-pool/stats":                 map[string]any{"get": op("ICCID pool counts by state")},
		"/admin/api/v1/iccid-pool/reserve":               map[string]any{"post": op("Reserve an ICCID from the pool")},
		"/admin/api/v1/iccid-pool/release":               map[string]any{"post": op("Return an ICCID to the pool")},
		"/admin/api/v1/iccid-pool/block":                 map[string]any{"post": op("Block an ICCID")},
		"/admin/api/v1/iccid-ranges":                     map[string]any{"get": op("List imported ICCID ranges"), "post": op("Import an ICCID range")},
		"/admin/api/v1/iccid-ranges/{id}":                map[string]any{"delete": op("Delete an ICCID range")},
		"/admin/api/v1/personalization":                  map[string]any{"get": op("List personalization records"), "post": op("Bulk import personalization records")},
		"/admin/api/v1/personalization/export":           map[string]any{"get": op("Export personalization (format=csv|json; includes K/OPc)")},
		"/admin/api/v1/personalization/{iccid}":          map[string]any{"get": op("Get a record (?reveal=1 to include K/OPc)"), "put": op("Create/replace a record"), "delete": op("Delete a record")},
	},
}

func op(summary string, params ...string) map[string]any {
	m := map[string]any{"summary": summary, "responses": map[string]any{"200": map[string]any{"description": "OK"}}}
	if len(params) > 0 && params[0] != "" {
		m["parameters"] = []map[string]string{{"name": "query", "in": "query", "description": params[0]}}
	}
	return m
}
