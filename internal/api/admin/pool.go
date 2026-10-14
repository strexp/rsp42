package admin

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/store"
)

type poolView struct {
	ICCID       string     `json:"iccid"`
	State       string     `json:"state"`
	EID         string     `json:"eid,omitempty"`
	BatchID     *int64     `json:"batchId,omitempty"`
	Note        string     `json:"note,omitempty"`
	AllocatedAt *time.Time `json:"allocatedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func toPoolView(e *store.ICCIDPoolEntry) poolView {
	return poolView{
		ICCID: e.ICCID, State: e.State, EID: e.EID, BatchID: e.BatchID,
		Note: e.Note, AllocatedAt: e.AllocatedAt, CreatedAt: e.CreatedAt,
	}
}

type rangeView struct {
	ID        int64     `json:"id"`
	Start     string    `json:"start"`
	End       string    `json:"end"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (h *Handler) listPool(w http.ResponseWriter, r *http.Request) {
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
	items, total, err := h.Pool.ListPage(q.Get("state"), q.Get("iccid"), size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]poolView, 0, len(items))
	for _, e := range items {
		views = append(views, toPoolView(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}

func (h *Handler) poolStats(w http.ResponseWriter, _ *http.Request) {
	counts, ranges, err := h.Pool.Stats()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"states": counts, "ranges": ranges, "available": counts["available"]})
}

func (h *Handler) reserveICCID(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EID string `json:"eid"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	iccid, err := h.Pool.Reserve(req.EID)
	if err != nil {
		writeErr(w, http.StatusConflict, "no available ICCID in the pool")
		return
	}
	h.audit(r, "reserveICCID", iccid, "Executed-Success", map[string]any{"eid": req.EID})
	writeJSON(w, http.StatusOK, map[string]any{"iccid": iccid, "state": "allocated"})
}

func (h *Handler) setICCIDState(w http.ResponseWriter, r *http.Request, state string) {
	var req struct {
		ICCID string `json:"iccid"`
		Note  string `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.ICCID == "" {
		writeErr(w, http.StatusBadRequest, "iccid is required")
		return
	}
	if err := h.Pool.SetState(normalizeICCID(req.ICCID), state, req.Note); err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	h.audit(r, "setICCIDState", req.ICCID, "Executed-Success", map[string]any{"state": state})
	writeJSON(w, http.StatusOK, map[string]any{"iccid": req.ICCID, "state": state})
}

func (h *Handler) releaseICCID(w http.ResponseWriter, r *http.Request) {
	h.setICCIDState(w, r, "available")
}

func (h *Handler) blockICCID(w http.ResponseWriter, r *http.Request) {
	h.setICCIDState(w, r, "blocked")
}

func (h *Handler) listRanges(w http.ResponseWriter, _ *http.Request) {
	items, err := h.Pool.ListRanges()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]rangeView, 0, len(items))
	for _, rg := range items {
		views = append(views, rangeView{ID: rg.ID, Start: rg.Start, End: rg.End, Note: rg.Note, CreatedAt: rg.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (h *Handler) importRange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Start string `json:"start"`
		End   string `json:"end"`
		Note  string `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id, inserted, skipped, err := h.Pool.ImportRange(req.Start, req.End, req.Note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "importICCIDRange", req.Start+".."+req.End, "Executed-Success",
		map[string]any{"rangeId": id, "inserted": inserted, "skipped": skipped})
	writeJSON(w, http.StatusCreated, map[string]any{"rangeId": id, "inserted": inserted, "skipped": skipped})
}

func (h *Handler) deleteRange(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid range id")
		return
	}
	removed, err := h.Pool.DeleteRange(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown range")
		return
	}
	h.audit(r, "deleteICCIDRange", strconv.FormatInt(id, 10), "Executed-Success", map[string]any{"removed": removed})
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed})
}
