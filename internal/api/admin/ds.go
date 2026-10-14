package admin

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/store"
)

// MountDS registers the read-only SM-DS management API (event records). Writes
// remain the ES12 machine interface.
func MountDS(r chi.Router, events *store.EventRepo) {
	r.Route("/admin/api/v1", func(r chi.Router) {
		r.Get("/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, openAPIDoc())
		})
		r.Get("/events", func(w http.ResponseWriter, req *http.Request) {
			listDSEvents(w, req, events)
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
