package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/service"
	"rsp42/internal/store"
)

// DSAdminConfig holds the SM-DS management API dependencies.
type DSAdminConfig struct {
	Events *store.EventRepo
	// Audit, when set, records admin event writes (N8).
	Audit *store.AuditRepo
	// DefaultTTL bounds the lifetime of admin-registered events; 0 means the
	// event never expires (the ES12 path uses smds.event_ttl).
	DefaultTTL time.Duration
}

// MountDS registers the SM-DS management API: read access to the event records
// plus the N8 write endpoints (event writes otherwise travel the ES12 machine
// interface).
func MountDS(r chi.Router, cfg DSAdminConfig) {
	r.Route("/admin/api/v1", func(r chi.Router) {
		r.Get("/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, openAPIDoc())
		})
		r.Get("/events", func(w http.ResponseWriter, req *http.Request) {
			listDSEvents(w, req, cfg.Events)
		})
		r.Post("/events", func(w http.ResponseWriter, req *http.Request) {
			createDSEvent(w, req, cfg)
		})
		r.Delete("/events/{id}", func(w http.ResponseWriter, req *http.Request) {
			deleteDSEvent(w, req, cfg)
		})
	})
}

type eventView struct {
	ID                  int64      `json:"id"`
	Tenant              string     `json:"tenant,omitempty"`
	EID                 string     `json:"eid"`
	EventID             string     `json:"eventId"`
	RSPServerAddress    string     `json:"rspServerAddress"`
	CallerOID           string     `json:"callerOid"`
	ICCID               string     `json:"iccid,omitempty"`
	MatchingID          string     `json:"matchingId,omitempty"`
	ForwardingIndicator bool       `json:"forwardingIndicator"`
	Cascaded            bool       `json:"cascaded"`
	RootEventID         string     `json:"rootEventId,omitempty"`
	RegisteredAt        time.Time  `json:"registeredAt"`
	ExpiresAt           *time.Time `json:"expiresAt,omitempty"`
	DeletedAt           *time.Time `json:"deletedAt,omitempty"`
}

// listDSEvents exposes the SM-DS event records with tenant, time-range and
// lifecycle filters (G20).
func listDSEvents(w http.ResponseWriter, r *http.Request, events *store.EventRepo) {
	q := r.URL.Query()
	size := clampSize(atoiDefault(q.Get("size"), defaultPageSize))
	page := clampPage(atoiDefault(q.Get("page"), 1))

	filter := store.EventFilter{
		EID: q.Get("eid"), EventID: q.Get("eventId"),
		ICCID: normalizeICCID(q.Get("iccid")), MatchingID: q.Get("matchingId"),
		Status: q.Get("status"), Sort: q.Get("sort"),
		Tenant: tenantFilter(r),
	}
	if t := parseTime(firstNonEmpty(q.Get("from"), q.Get("since"))); t != nil {
		filter.Since = t
	}
	if t := parseTime(firstNonEmpty(q.Get("to"), q.Get("until"))); t != nil {
		filter.Until = t
	}
	recs, total, err := events.ListFiltered(filter, size, (page-1)*size, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	views := make([]eventView, 0, len(recs))
	for _, rec := range recs {
		views = append(views, eventView{
			ID: rec.ID, Tenant: rec.TenantID, EID: rec.EID, EventID: rec.EventID,
			RSPServerAddress: rec.RSPServerAddress, CallerOID: rec.CallerOID,
			ICCID: rec.ICCID, MatchingID: rec.MatchingID,
			ForwardingIndicator: rec.ForwardingIndicator, Cascaded: rec.Cascaded,
			RootEventID: rec.RootEventID, RegisteredAt: rec.RegisteredAt,
			ExpiresAt: rec.ExpiresAt, DeletedAt: rec.DeletedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}

// createDSEvent registers an event through the management API (N8). It exists
// for the edge cases where esim42 cannot use ES12 (no caller certificate), and
// mirrors the ES12 registration semantics: an EventID is generated when
// omitted, and re-using one is a 409.
func createDSEvent(w http.ResponseWriter, r *http.Request, cfg DSAdminConfig) {
	if cfg.Events == nil {
		writeErr(w, http.StatusNotImplemented, "event store not configured")
		return
	}
	var req struct {
		EID                 string `json:"eid"`
		EventID             string `json:"eventId"`
		RSPServerAddress    string `json:"rspServerAddress"`
		CallerOID           string `json:"callerOid"`
		Tenant              string `json:"tenant"`
		ICCID               string `json:"iccid"`
		MatchingID          string `json:"matchingId"`
		ForwardingIndicator bool   `json:"forwardingIndicator"`
		TTL                 string `json:"ttl"`
		ExpiresAt           string `json:"expiresAt"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.EID == "" || req.RSPServerAddress == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid_request", "eid and rspServerAddress are required"))
		return
	}
	tenant := req.Tenant
	if tenant == "" {
		tenant = r.URL.Query().Get("tenant")
	}
	eventID := req.EventID
	if eventID == "" {
		eventID = service.NewEventID()
	}
	rec := &store.EventRecord{
		EID: req.EID, EventID: eventID, RSPServerAddress: req.RSPServerAddress,
		CallerOID:           firstNonEmpty(req.CallerOID, adminActor),
		ForwardingIndicator: req.ForwardingIndicator,
		TenantID:            tenant,
		ICCID:               normalizeICCID(req.ICCID),
		MatchingID:          req.MatchingID,
		RegisteredAt:        time.Now().UTC(),
	}
	switch {
	case req.ExpiresAt != "":
		t := parseTime(req.ExpiresAt)
		if t == nil {
			writeJSON(w, http.StatusBadRequest, errorBody("invalid_request", "expiresAt must be an RFC3339 timestamp or a date"))
			return
		}
		rec.ExpiresAt = t
	case req.TTL != "":
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d < 0 {
			writeJSON(w, http.StatusBadRequest, errorBody("invalid_request", "ttl must be a non-negative duration"))
			return
		}
		exp := rec.RegisteredAt.Add(d)
		rec.ExpiresAt = &exp
	case cfg.DefaultTTL > 0:
		exp := rec.RegisteredAt.Add(cfg.DefaultTTL)
		rec.ExpiresAt = &exp
	}
	if _, err := cfg.Events.Insert(rec); err != nil {
		if errors.Is(err, store.ErrEventIDInUse) {
			writeJSON(w, http.StatusConflict, errorBody("event_id_in_use", "EventID already used for this EID"))
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditDS(cfg, r, tenant, "registerEvent", rec.EID, map[string]any{"eventId": eventID, "iccid": rec.ICCID})
	writeJSON(w, http.StatusCreated, toEventView(rec))
}

// deleteDSEvent soft-deletes an event (N8). The ES12 delete path keeps the
// record for audit; this endpoint does the same.
func deleteDSEvent(w http.ResponseWriter, r *http.Request, cfg DSAdminConfig) {
	if cfg.Events == nil {
		writeErr(w, http.StatusNotImplemented, "event store not configured")
		return
	}
	id, err := parseID(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid_request", "invalid event id"))
		return
	}
	ok, err := cfg.Events.SoftDelete(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown or already deleted event")
		return
	}
	auditDS(cfg, r, r.URL.Query().Get("tenant"), "deleteEvent", chi.URLParam(r, "id"), nil)
	w.WriteHeader(http.StatusNoContent)
}

// auditDS records an admin event write.
func auditDS(cfg DSAdminConfig, r *http.Request, tenant, fn, subject string, detail any) {
	if cfg.Audit == nil {
		return
	}
	dj := ""
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			dj = string(b)
		}
	}
	_ = cfg.Audit.Insert(&store.AuditEntry{
		TenantID: tenant, Actor: adminActor, Interface: "admin", Function: fn,
		Subject: subject, Outcome: "Executed-Success", RemoteAddr: r.RemoteAddr, DetailJSON: dj,
	})
}

func toEventView(rec *store.EventRecord) eventView {
	return eventView{
		ID: rec.ID, Tenant: rec.TenantID, EID: rec.EID, EventID: rec.EventID,
		RSPServerAddress: rec.RSPServerAddress, CallerOID: rec.CallerOID,
		ICCID: rec.ICCID, MatchingID: rec.MatchingID,
		ForwardingIndicator: rec.ForwardingIndicator, Cascaded: rec.Cascaded,
		RootEventID: rec.RootEventID, RegisteredAt: rec.RegisteredAt,
		ExpiresAt: rec.ExpiresAt, DeletedAt: rec.DeletedAt,
	}
}
