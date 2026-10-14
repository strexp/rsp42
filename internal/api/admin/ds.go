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
			writeJSON(w, http.StatusOK, map[string]any{
				"openapi": "3.0.3",
				"info":    map[string]any{"title": "rsp42 SM-DS management API", "version": "0.1.0"},
				"paths": map[string]any{
					"/admin/api/v1/events": map[string]any{"get": op("List SM-DS event records", "eid, eventId, page, size")},
				},
			})
		})
		r.Get("/events", func(w http.ResponseWriter, req *http.Request) {
			listDSEvents(w, req, events)
		})
	})
}

type eventView struct {
	ID                  int64      `json:"id"`
	EID                 string     `json:"eid"`
	EventID             string     `json:"eventId"`
	RSPServerAddress    string     `json:"rspServerAddress"`
	CallerOID           string     `json:"callerOid"`
	ForwardingIndicator bool       `json:"forwardingIndicator"`
	Cascaded            bool       `json:"cascaded"`
	RootEventID         string     `json:"rootEventId,omitempty"`
	RegisteredAt        time.Time  `json:"registeredAt"`
	ExpiresAt           *time.Time `json:"expiresAt,omitempty"`
}

func listDSEvents(w http.ResponseWriter, r *http.Request, events *store.EventRepo) {
	q := r.URL.Query()
	size := atoiDefault(q.Get("size"), defaultPageSize)
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}
	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}

	eid, eventID := q.Get("eid"), q.Get("eventId")
	var (
		recs []*store.EventRecord
		err  error
	)
	switch {
	case eid != "" && eventID != "":
		recs, err = events.ListByEIDEventID(eid, eventID)
	case eid != "":
		recs, err = events.ListByEID(eid)
	default:
		recs, err = events.ListAll()
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	total := len(recs)
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	views := make([]eventView, 0, end-start)
	for _, rec := range recs[start:end] {
		views = append(views, eventView{
			ID: rec.ID, EID: rec.EID, EventID: rec.EventID, RSPServerAddress: rec.RSPServerAddress,
			CallerOID: rec.CallerOID, ForwardingIndicator: rec.ForwardingIndicator, Cascaded: rec.Cascaded,
			RootEventID: rec.RootEventID, RegisteredAt: rec.RegisteredAt, ExpiresAt: rec.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}
