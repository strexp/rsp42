package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/service"
	"rsp42/internal/store"
)

const maxBatchSize = 1000

type batchView struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name,omitempty"`
	ProfileType string    `json:"profileType,omitempty"`
	State       string    `json:"state"`
	Total       int       `json:"total"`
	Note        string    `json:"note,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func toBatchView(b *store.DownloadBatch) batchView {
	return batchView{
		ID: b.ID, Name: b.Name, ProfileType: b.ProfileType, State: b.State,
		Total: b.Total, Note: b.Note, CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt,
	}
}

type createBatchReq struct {
	Name        string `json:"name"`
	Count       int    `json:"count"`
	ProfileType string `json:"profileType"`
	EID         string `json:"eid"`
	UPPTemplate string `json:"uppTemplate"`
	Note        string `json:"note"`
	Tenant      string `json:"tenant"`
}

func (h *Handler) createBatch(w http.ResponseWriter, r *http.Request) {
	var req createBatchReq
	if !readJSON(w, r, &req) {
		return
	}
	if req.Count < 1 || req.Count > maxBatchSize {
		writeErr(w, http.StatusBadRequest, "count must be between 1 and "+strconv.Itoa(maxBatchSize))
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	id, err := h.Batch.Insert(&store.DownloadBatch{
		Name: req.Name, TenantID: tenant, ProfileType: req.ProfileType, State: "Open", Total: req.Count, Note: req.Note,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	allocated := 0
	for i := 0; i < req.Count; i++ {
		p, err := h.Inventory.Allocate(service.AllocateRequest{
			EID: req.EID, ProfileType: req.ProfileType, UPPTemplate: req.UPPTemplate, Tenant: tenant,
		})
		if err != nil {
			h.audit(r, "createBatch", strconv.FormatInt(id, 10), "Failed", err.Error())
			if errors.Is(err, service.ErrQuotaExceeded) {
				writeQuotaErr(w, err)
				return
			}
			writeErr(w, http.StatusInternalServerError, "allocated "+strconv.Itoa(allocated)+" of "+strconv.Itoa(req.Count)+": "+err.Error())
			return
		}
		p.BatchID = &id
		_ = h.Profiles.Update(p)
		allocated++
	}
	h.audit(r, "createBatch", strconv.FormatInt(id, 10), "Executed-Success", map[string]any{"count": allocated})
	b, _ := h.Batch.Get(id)
	writeJSON(w, http.StatusCreated, toBatchView(b))
}

func (h *Handler) listBatches(w http.ResponseWriter, r *http.Request) {
	page, size := parsePage(r)
	items, total, err := h.Batch.List(scopeTenantParam(r), size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]batchView, 0, len(items))
	for _, b := range items {
		views = append(views, toBatchView(b))
	}
	writeListEnvelope(w, views, page, size, total)
}

func (h *Handler) getBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := batchID(w, r)
	if !ok {
		return
	}
	b, err := h.Batch.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown batch")
		return
	}
	// State breakdown for the batch's profiles.
	counts := map[string]int{}
	for _, s := range []store.ProfileState{
		store.StateAvailable, store.StateAllocated, store.StateLinked, store.StateConfirmed,
		store.StateReleased, store.StateDownloaded, store.StateInstalled, store.StateError, store.StateUnavailable,
	} {
		_, total, err := h.Profiles.ListFiltered(store.ProfileFilter{BatchID: &id, State: string(s)}, 1, 0, "")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if total > 0 {
			counts[string(s)] = total
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"batch": toBatchView(b), "states": counts})
}

func (h *Handler) listBatchItems(w http.ResponseWriter, r *http.Request) {
	id, ok := batchID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	page, size := parsePage(r)
	items, total, err := h.Profiles.ListFiltered(store.ProfileFilter{BatchID: &id, State: q.Get("state")}, size, (page-1)*size, q.Get("sort"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]profileView, 0, len(items))
	for _, p := range items {
		views = append(views, toProfileView(p))
	}
	writeListEnvelope(w, views, page, size, total)
}

func (h *Handler) confirmBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := batchID(w, r)
	if !ok {
		return
	}
	var req struct {
		Release bool `json:"release"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	applied, failed := h.applyToBatch(r, id, func(p *store.Profile) error {
		_, err := h.Orders.Confirm(p.ICCID, req.Release)
		return err
	})
	if failed > 0 {
		h.Batch.UpdateState(id, "Completed")
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": applied, "failed": failed})
}

func (h *Handler) cancelBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := batchID(w, r)
	if !ok {
		return
	}
	var req struct {
		FinalStatus string `json:"finalStatus"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	unavailable := strings.EqualFold(req.FinalStatus, "Unavailable")
	applied, failed := h.applyToBatch(r, id, func(p *store.Profile) error {
		_, err := h.Orders.Cancel(p.ICCID, unavailable)
		return err
	})
	_ = h.Batch.UpdateState(id, "Cancelled")
	writeJSON(w, http.StatusOK, map[string]any{"applied": applied, "failed": failed})
}

func (h *Handler) deleteBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := batchID(w, r)
	if !ok {
		return
	}
	if err := h.Batch.Delete(id); err != nil {
		writeErr(w, http.StatusNotFound, "unknown batch")
		return
	}
	h.audit(r, "deleteBatch", strconv.FormatInt(id, 10), "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}

// applyToBatch runs fn over every profile of the batch, returning applied/failed.
func (h *Handler) applyToBatch(r *http.Request, id int64, fn func(*store.Profile) error) (applied, failed int) {
	items, _, err := h.Profiles.ListFiltered(store.ProfileFilter{BatchID: &id}, maxBatchSize, 0, "")
	if err != nil {
		return 0, 0
	}
	for _, p := range items {
		if err := fn(p); err != nil {
			failed++
			continue
		}
		applied++
	}
	h.audit(r, "batchApply", strconv.FormatInt(id, 10), "Executed-Success", map[string]any{"applied": applied, "failed": failed})
	return applied, failed
}

func batchID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid batch id")
		return 0, false
	}
	return id, true
}

// bulkProfiles applies an action to a list of ICCIDs.
func (h *Handler) bulkProfiles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action      string   `json:"action"` // confirm|cancel|release|delete
		ICCIDs      []string `json:"iccids"`
		Release     bool     `json:"release"`
		FinalStatus string   `json:"finalStatus"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.ICCIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "iccids is required")
		return
	}
	type result struct {
		ICCID string `json:"iccid"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(req.ICCIDs))
	for _, raw := range req.ICCIDs {
		iccid := normalizeICCID(raw)
		var err error
		switch req.Action {
		case "confirm":
			_, err = h.Orders.Confirm(iccid, req.Release)
		case "cancel":
			_, err = h.Orders.Cancel(iccid, strings.EqualFold(req.FinalStatus, "Unavailable"))
		case "release":
			_, err = h.Orders.Release(iccid)
		case "delete":
			err = h.Profiles.Delete(iccid)
		default:
			writeErr(w, http.StatusBadRequest, "unknown action "+req.Action)
			return
		}
		res := result{ICCID: iccid, OK: err == nil}
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				res.Error = "unknown ICCID"
			} else {
				res.Error = err.Error()
			}
		}
		results = append(results, res)
	}
	h.audit(r, "bulkProfiles", req.Action, "Executed-Success", map[string]any{"count": len(req.ICCIDs)})
	writeJSON(w, http.StatusOK, map[string]any{"action": req.Action, "results": results})
}
