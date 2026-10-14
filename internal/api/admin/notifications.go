package admin

import (
	"net/http"
	"time"

	"rsp42/internal/store"
)

type notificationView struct {
	ID            int64     `json:"id"`
	EID           string    `json:"eid,omitempty"`
	SeqNumber     int64     `json:"seqNumber"`
	Operation     string    `json:"operation"`
	ICCID         string    `json:"iccid,omitempty"`
	TransactionID string    `json:"transactionId,omitempty"`
	SignatureOK   bool      `json:"signatureOk"`
	Processed     bool      `json:"processed"`
	ReceivedAt    time.Time `json:"receivedAt"`
}

// listNotifications exposes received ES9+ notifications directly (previously
// only reachable through a profile timeline).
func (h *Handler) listNotifications(w http.ResponseWriter, r *http.Request) {
	if h.Notifs == nil {
		writeErr(w, http.StatusNotImplemented, "notification store not configured")
		return
	}
	q := r.URL.Query()
	size := clampSize(atoiDefault(q.Get("size"), defaultPageSize))
	page := clampPage(atoiDefault(q.Get("page"), 1))
	filter := store.NotificationFilter{ICCID: normalizeICCID(q.Get("iccid")), EID: q.Get("eid")}
	if t := parseTime(q.Get("from")); t != nil {
		filter.Since = t
	}
	if t := parseTime(q.Get("to")); t != nil {
		filter.Until = t
	}
	items, total, err := h.Notifs.ListFiltered(filter, size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]notificationView, 0, len(items))
	for _, n := range items {
		views = append(views, notificationView{
			ID: n.ID, EID: n.EID, SeqNumber: n.SeqNumber, Operation: n.Operation,
			ICCID: n.ICCID, TransactionID: n.TransactionID,
			SignatureOK: n.SignatureOK, Processed: n.Processed, ReceivedAt: n.ReceivedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}
