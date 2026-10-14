package admin

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/store"
)

type poolView struct {
	ICCID         string     `json:"iccid"`
	Tenant        string     `json:"tenant,omitempty"`
	State         string     `json:"state"`
	EID           string     `json:"eid,omitempty"`
	Reference     string     `json:"reference,omitempty"`
	ProfileID     *int64     `json:"profileId,omitempty"`
	BatchID       *int64     `json:"batchId,omitempty"`
	Note          string     `json:"note,omitempty"`
	ReservedUntil *time.Time `json:"reservedUntil,omitempty"`
	AllocatedAt   *time.Time `json:"allocatedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
}

func toPoolView(e *store.ICCIDPoolEntry) poolView {
	return poolView{
		ICCID: e.ICCID, Tenant: e.TenantID, State: e.State, EID: e.EID,
		Reference: e.Reference, ProfileID: e.ProfileID, BatchID: e.BatchID,
		Note: e.Note, ReservedUntil: e.ReservedUntil, AllocatedAt: e.AllocatedAt, CreatedAt: e.CreatedAt,
	}
}

type rangeView struct {
	ID        int64     `json:"id"`
	Tenant    string    `json:"tenant,omitempty"`
	Start     string    `json:"start"`
	End       string    `json:"end"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (h *Handler) listPool(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := clampSize(atoiDefault(q.Get("size"), defaultPageSize))
	page := clampPage(atoiDefault(q.Get("page"), 1))
	items, total, err := h.Pool.ListPage(q.Get("state"), q.Get("iccid"), tenantFilter(r), size, (page-1)*size)
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

func (h *Handler) poolStats(w http.ResponseWriter, r *http.Request) {
	filter := tenantFilter(r)
	counts, ranges, err := h.Pool.Stats(filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"states": counts, "ranges": ranges, "available": counts["available"]}
	if h.Perso != nil && filter != nil {
		if n, err := h.Perso.CountUnbound(*filter); err == nil {
			out["credentials_unbound"] = n
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// reserveICCID takes an ICCID from the tenant's pool and, when the tenant has
// unbound credentials, pairs it with the next IMSI (G6).
func (h *Handler) reserveICCID(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EID        string `json:"eid"`
		Tenant     string `json:"tenant"`
		Reference  string `json:"reference"`
		TTLSeconds int    `json:"ttlSeconds"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	ttl := h.DefaultReserveTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	iccid, err := h.Pool.Reserve(tenant, req.EID, req.Reference, ttl)
	if err != nil {
		writeErr(w, http.StatusConflict, "no available ICCID in the pool")
		return
	}
	resp := map[string]any{"iccid": iccid, "state": "allocated", "tenant": tenant}
	if h.Perso != nil {
		imsi, perr := h.Perso.ReservePair(tenant, iccid)
		if perr != nil {
			writeErr(w, http.StatusInternalServerError, perr.Error())
			return
		}
		if imsi != "" {
			resp["imsi"] = imsi
		}
	}
	h.audit(r, "reserveICCID", iccid, "Executed-Success", map[string]any{"eid": req.EID, "tenant": tenant, "imsi": resp["imsi"]})
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) setICCIDState(w http.ResponseWriter, r *http.Request, state string) {
	var req struct {
		ICCID  string `json:"iccid"`
		Tenant string `json:"tenant"`
		Note   string `json:"note"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.ICCID == "" {
		writeErr(w, http.StatusBadRequest, "iccid is required")
		return
	}
	iccid := normalizeICCID(req.ICCID)
	tenant, _ := h.effectiveTenant(r, req.Tenant)
	if err := h.Pool.SetState(iccid, state, req.Note); err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	if state == "available" && h.Perso != nil {
		_ = h.Perso.UnbindPair(tenant, iccid)
	}
	h.audit(r, "setICCIDState", iccid, "Executed-Success", map[string]any{"state": state, "tenant": tenant})
	writeJSON(w, http.StatusOK, map[string]any{"iccid": iccid, "state": state})
}

func (h *Handler) releaseICCID(w http.ResponseWriter, r *http.Request) {
	h.setICCIDState(w, r, "available")
}

func (h *Handler) blockICCID(w http.ResponseWriter, r *http.Request) {
	h.setICCIDState(w, r, "blocked")
}

func (h *Handler) listRanges(w http.ResponseWriter, r *http.Request) {
	items, err := h.Pool.ListRanges(tenantFilter(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]rangeView, 0, len(items))
	for _, rg := range items {
		views = append(views, rangeView{ID: rg.ID, Tenant: rg.TenantID, Start: rg.Start, End: rg.End, Note: rg.Note, CreatedAt: rg.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (h *Handler) importRange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Start  string `json:"start"`
		End    string `json:"end"`
		Note   string `json:"note"`
		Tenant string `json:"tenant"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	id, inserted, skipped, err := h.Pool.ImportRange(tenant, req.Start, req.End, req.Note)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "importICCIDRange", req.Start+".."+req.End, "Executed-Success",
		map[string]any{"rangeId": id, "inserted": inserted, "skipped": skipped, "tenant": tenant})
	writeJSON(w, http.StatusCreated, map[string]any{"rangeId": id, "inserted": inserted, "skipped": skipped, "tenant": tenant})
}

func (h *Handler) deleteRange(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid range id")
		return
	}
	removed, err := h.Pool.DeleteRange(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown range")
		return
	}
	h.audit(r, "deleteICCIDRange", chi.URLParam(r, "id"), "Executed-Success", map[string]any{"removed": removed})
	writeJSON(w, http.StatusOK, map[string]any{"removed": removed})
}
