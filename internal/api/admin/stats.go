package admin

import (
	"net/http"

	"rsp42/internal/store"
)

// profileStats aggregates profile counts for the operator dashboard (G8).
func (h *Handler) profileStats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := profileFilterFromQuery(q)
	groupBy := q.Get("groupBy")
	buckets, err := h.Profiles.Stats(filter, groupBy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, total, err := h.Profiles.ListFiltered(filter, 1, 0, "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if groupBy == "" {
		groupBy = "state"
	}
	writeJSON(w, http.StatusOK, map[string]any{"groupBy": groupBy, "total": total, "buckets": buckets})
}

// auditStats aggregates audit counts for the platform dashboard (G8).
func (h *Handler) auditStats(w http.ResponseWriter, r *http.Request) {
	if h.Audit == nil {
		writeErr(w, http.StatusNotImplemented, "audit log not configured")
		return
	}
	q := r.URL.Query()
	filter := store.AuditFilter{
		Interface: q.Get("interface"), Function: q.Get("function"),
		Subject: q.Get("subject"), Actor: q.Get("actor"), Outcome: q.Get("outcome"),
		Tenant: tenantFilter(r),
	}
	if t := parseTime(q.Get("from")); t != nil {
		filter.Since = t
	}
	if t := parseTime(q.Get("to")); t != nil {
		filter.Until = t
	}
	groupBy := q.Get("groupBy")
	buckets, err := h.Audit.Stats(filter, groupBy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, total, err := h.Audit.ListFiltered(filter, 1, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if groupBy == "" {
		groupBy = "function"
	}
	writeJSON(w, http.StatusOK, map[string]any{"groupBy": groupBy, "total": total, "buckets": buckets})
}
