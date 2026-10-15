package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"rsp42/internal/api/adminhttp"
	"rsp42/internal/iccid"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/store"
)

// callbackView is the management-API representation of a queued outbound
// ES2+ progress notification. Payload is returned as a parsed JSON object, not
// as the raw stored string.
type callbackView struct {
	ID          int64      `json:"id"`
	URL         string     `json:"url"`
	PointID     int        `json:"notificationPointId"`
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	NextRetryAt *time.Time `json:"nextAttemptAt,omitempty"`
	Response    string     `json:"response,omitempty"`
	Payload     any        `json:"payload"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func toCallbackView(c *store.Callback) callbackView {
	v := callbackView{
		ID: c.ID, URL: c.URL, PointID: c.PointID, State: c.Status,
		Attempts: c.Attempts, NextRetryAt: c.NextRetryAt, Response: c.Response,
		CreatedAt: c.CreatedAt,
	}
	if c.Payload != "" {
		var parsed any
		if err := json.Unmarshal([]byte(c.Payload), &parsed); err == nil {
			v.Payload = parsed
		} else {
			v.Payload = c.Payload
		}
	}
	return v
}

// listCallbacks exposes the outbound callback queue (N2). Without it, a dead
// letter is invisible: the delivery status of a download/install would be lost
// with no way to inspect or re-drive it.
func (h *Handler) listCallbacks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, size := adminhttp.ParsePage(r)
	filter := store.CallbackFilter{
		Status: q.Get("state"),
		ICCID:  iccid.Normalize(q.Get("iccid")),
		Tenant: adminhttp.TenantFilter(r),
	}
	if t := adminhttp.ParseTime(adminhttp.FirstNonEmpty(q.Get("from"), q.Get("since"))); t != nil {
		filter.Since = t
	}
	if t := adminhttp.ParseTime(adminhttp.FirstNonEmpty(q.Get("to"), q.Get("until"))); t != nil {
		filter.Until = t
	}
	items, total, err := h.Callbacks.ListFiltered(filter, size, (page-1)*size)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]callbackView, 0, len(items))
	for _, c := range items {
		views = append(views, toCallbackView(c))
	}
	adminhttp.WriteListEnvelope(w, views, page, size, total)
}

// retryCallback re-queues one dead-lettered callback.
func (h *Handler) retryCallback(w http.ResponseWriter, r *http.Request) {
	id, err := adminhttp.ParseID(chi.URLParam(r, "id"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusBadRequest, "invalid callback id")
		return
	}
	if err := h.Callbacks.Requeue(id); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			adminhttp.WriteErr(w, http.StatusNotFound, "unknown callback")
		case errors.Is(err, store.ErrConflict):
			adminhttp.WriteJSON(w, http.StatusConflict, adminhttp.ErrorBody("conflict", "callback is not in a dead-letter state"))
		default:
			adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.audit(r, "retryCallback", strconv.FormatInt(id, 10), "Executed-Success", nil)
	got, err := h.Callbacks.Get(id)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	adminhttp.WriteJSON(w, http.StatusOK, toCallbackView(got))
}

// retryDeadCallbacks re-queues a batch of dead-lettered callbacks.
func (h *Handler) retryDeadCallbacks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant string `json:"tenant"`
		Before string `json:"before"`
		Limit  int    `json:"limit"`
	}
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	before := time.Now().UTC()
	if req.Before != "" {
		t := adminhttp.ParseTime(req.Before)
		if t == nil {
			adminhttp.WriteErr(w, http.StatusBadRequest, "before must be an RFC3339 timestamp or a date")
			return
		}
		before = *t
	}
	var tenantPtr *string
	if req.Tenant != "" || r.URL.Query().Has("tenant") {
		tenantPtr = &tenant
	}
	n, err := h.Callbacks.RequeueDead(tenantPtr, before, req.Limit)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "retryCallback", "retry-dead", "Executed-Success", map[string]any{"requeued": n})
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"requeued": n})
}
