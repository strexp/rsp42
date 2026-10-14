package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"rsp42/internal/store"
)

type auditView struct {
	Time       time.Time `json:"time"`
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
		Time: e.TS, Actor: e.Actor, Interface: e.Interface, Function: e.Function,
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
	filter := store.AuditFilter{
		Interface: q.Get("interface"), Function: q.Get("function"),
		Subject: q.Get("subject"), Actor: q.Get("actor"), Outcome: q.Get("outcome"),
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Since = &t
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			filter.Until = &t
		}
	}
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
