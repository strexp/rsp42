package admin

import (
	"net/http"
	"rsp42/internal/api/adminhttp"
	"rsp42/internal/iccid"
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
		adminhttp.WriteErr(w, http.StatusNotImplemented, "notification store not configured")
		return
	}
	q := r.URL.Query()
	page, size := adminhttp.ParsePage(r)
	filter := store.NotificationFilter{ICCID: iccid.Normalize(q.Get("iccid")), EID: q.Get("eid")}
	if t := adminhttp.ParseTime(q.Get("from")); t != nil {
		filter.Since = t
	}
	if t := adminhttp.ParseTime(q.Get("to")); t != nil {
		filter.Until = t
	}
	items, total, err := h.Notifs.ListFiltered(filter, size, (page-1)*size)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
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
	adminhttp.WriteListEnvelope(w, views, page, size, total)
}
