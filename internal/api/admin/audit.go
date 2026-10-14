package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"rsp42/internal/store"
)

type auditView struct {
	ID         int64     `json:"id"`
	Time       time.Time `json:"time"`
	Tenant     string    `json:"tenant,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	Function   string    `json:"function,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Outcome    string    `json:"outcome,omitempty"`
	StatusCode string    `json:"statusCode,omitempty"`
	RemoteAddr string    `json:"remoteAddr,omitempty"`
	Detail     any       `json:"detail,omitempty"`
}

func toAuditView(e *store.AuditEntry) auditView {
	v := auditView{
		ID:   e.ID,
		Time: e.TS, Tenant: e.TenantID, Actor: e.Actor, Interface: e.Interface, Function: e.Function,
		Subject: e.Subject, Outcome: e.Outcome, StatusCode: e.StatusCode, RemoteAddr: e.RemoteAddr,
	}
	if e.DetailJSON != "" {
		var anyJSON any
		if err := json.Unmarshal([]byte(e.DetailJSON), &anyJSON); err == nil {
			v.Detail = anyJSON
		} else {
			v.Detail = e.DetailJSON
		}
	}
	return v
}

// listAudit exposes the audit log (management edits, ES9+/ES11/ES2+ requests).
func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request) {
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
	// `since`/`until` are accepted as aliases for `from`/`to`.
	if t := parseTime(firstNonEmpty(q.Get("from"), q.Get("since"))); t != nil {
		filter.Since = t
	}
	if t := parseTime(firstNonEmpty(q.Get("to"), q.Get("until"))); t != nil {
		filter.Until = t
	}

	// N1: afterId switches to the monotonic incremental cursor. It is mutually
	// exclusive with the page/size paging mode, whose OFFSET drifts under
	// concurrent writes.
	if q.Has("afterId") {
		if q.Has("page") || q.Has("size") {
			writeJSON(w, http.StatusBadRequest, errorBody("invalid_request",
				"afterId is mutually exclusive with page/size"))
			return
		}
		afterID, err := strconv.ParseInt(q.Get("afterId"), 10, 64)
		if err != nil || afterID < 0 {
			writeJSON(w, http.StatusBadRequest, errorBody("invalid_request",
				"afterId must be a non-negative integer"))
			return
		}
		limit := atoiDefault(q.Get("limit"), 500)
		if limit < 1 {
			limit = 500
		}
		if limit > maxPageSize {
			limit = maxPageSize
		}
		entries, err := h.Audit.ListAfterID(filter, afterID, limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		views := make([]auditView, 0, len(entries))
		for _, e := range entries {
			views = append(views, toAuditView(e))
		}
		next := afterID
		if len(entries) > 0 {
			next = entries[len(entries)-1].ID
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": views, "nextAfterId": next, "hasMore": len(entries) == limit,
		})
		return
	}

	size := clampSize(atoiDefault(q.Get("size"), defaultPageSize))
	page := clampPage(atoiDefault(q.Get("page"), 1))
	entries, total, err := h.Audit.ListFiltered(filter, size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]auditView, 0, len(entries))
	for _, e := range entries {
		views = append(views, toAuditView(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}
