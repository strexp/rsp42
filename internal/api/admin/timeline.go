package admin

import (
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/adminhttp"
	"rsp42/internal/iccid"
)

// profileTimeline merges order-audit rows, received notifications, download
// sessions and audit entries for an ICCID into a single (newest-first) list.
func (h *Handler) profileTimeline(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	type event struct {
		Time    time.Time `json:"time"`
		Kind    string    `json:"kind"` // order | notification | session | audit
		Action  string    `json:"action"`
		Detail  string    `json:"detail,omitempty"`
		Signed  *bool     `json:"signed,omitempty"`
		Success *bool     `json:"processed,omitempty"`
	}
	events := []event{}
	if h.OrderRepo != nil {
		orders, err := h.OrderRepo.ListByICCID(iccid)
		if err != nil {
			adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, o := range orders {
			events = append(events, event{Time: o.CreatedAt, Kind: "order", Action: o.Action, Detail: o.MatchingID})
		}
	}
	if h.Notifs != nil {
		notifs, err := h.Notifs.ListByICCID(iccid)
		if err != nil {
			adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, n := range notifs {
			sig, proc := n.SignatureOK, n.Processed
			events = append(events, event{
				Time: n.ReceivedAt, Kind: "notification", Action: n.Operation,
				Detail: n.TransactionID, Signed: &sig, Success: &proc,
			})
		}
	}
	if p, err := h.Profiles.GetByICCID(iccid); err == nil && h.Sessions != nil {
		sessions, err := h.Sessions.ListByProfileID(p.ID)
		if err == nil {
			for _, s := range sessions {
				events = append(events, event{
					Time: s.CreatedAt, Kind: "session",
					Action: s.State, Detail: s.TransactionID,
				})
			}
		}
	}
	if h.Audit != nil {
		entries, err := h.Audit.ListBySubject(iccid, adminhttp.MaxPageSize)
		if err == nil {
			for _, e := range entries {
				events = append(events, event{
					Time: e.TS, Kind: "audit", Action: e.Interface + ":" + e.Function, Detail: e.Outcome,
				})
			}
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"iccid": iccid, "events": events})
}
