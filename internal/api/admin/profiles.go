package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/activationcode"
	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

const (
	defaultPageSize = 50
	maxPageSize     = 500
)

// profileView is the API representation of a profile (no cc_hash or secrets).
type profileView struct {
	ICCID            string     `json:"iccid"`
	IMSI             string     `json:"imsi,omitempty"`
	ProfileType      string     `json:"profileType,omitempty"`
	EID              string     `json:"eid,omitempty"`
	State            string     `json:"state"`
	MatchingID       string     `json:"matchingId,omitempty"`
	CCRequired       bool       `json:"ccRequired"`
	SMDSAddress      string     `json:"smdsAddress,omitempty"`
	UPPTemplate      string     `json:"uppTemplate,omitempty"`
	PPRIds           string     `json:"pprIds,omitempty"`
	DownloadAttempts int        `json:"downloadAttempts"`
	CCAttempts       int        `json:"ccAttempts"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	InstalledAt      *time.Time `json:"installedAt,omitempty"`
	ErrorReason      string     `json:"errorReason,omitempty"`
}

func toProfileView(p *store.Profile) profileView {
	v := profileView{
		ICCID: p.ICCID, IMSI: p.IMSI, ProfileType: p.ProfileType, EID: p.EID,
		State: string(p.State), MatchingID: p.MatchingID, CCRequired: p.CCRequired,
		SMDSAddress: p.SMDSAddress, UPPTemplate: p.UPPTemplate,
		DownloadAttempts: p.DownloadAttempts, CCAttempts: p.CCAttempts,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, InstalledAt: p.InstalledAt,
		ErrorReason: p.ErrorReason,
	}
	if len(p.PPRIds) > 0 {
		v.PPRIds = hex.EncodeToString(p.PPRIds)
	}
	return v
}

func (h *Handler) listProfiles(w http.ResponseWriter, r *http.Request) {
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
	filter := store.ProfileFilter{
		State: q.Get("state"), EID: q.Get("eid"), ICCID: q.Get("iccid"), Query: q.Get("q"),
	}
	items, total, err := h.Profiles.ListFiltered(filter, size, (page-1)*size, q.Get("sort"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]profileView, 0, len(items))
	for _, p := range items {
		views = append(views, toProfileView(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	p, err := h.Profiles.GetByICCID(normalizeICCID(chi.URLParam(r, "iccid")))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	writeJSON(w, http.StatusOK, toProfileView(p))
}

type createProfileReq struct {
	ICCID       string `json:"iccid"`
	EID         string `json:"eid"`
	ProfileType string `json:"profileType"`
	MatchingID  string `json:"matchingId"`
	SMDSAddress string `json:"smdsAddress"`
}

func (h *Handler) createProfile(w http.ResponseWriter, r *http.Request) {
	var req createProfileReq
	if !readJSON(w, r, &req) {
		return
	}
	p, err := h.Inventory.Allocate(req.EID, req.ProfileType, req.ICCID)
	if err != nil {
		h.audit(r, "createProfile", req.ICCID, "Failed", req)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.MatchingID != "" || req.SMDSAddress != "" {
		if req.MatchingID != "" {
			p.MatchingID = req.MatchingID
		}
		if req.SMDSAddress != "" {
			p.SMDSAddress = req.SMDSAddress
		}
		_ = h.Profiles.Update(p)
	}
	h.recordOrder(p.ICCID, p.EID, p.MatchingID, "downloadOrder", req)
	h.audit(r, "createProfile", p.ICCID, "Executed-Success", req)
	writeJSON(w, http.StatusCreated, toProfileView(p))
}

type updateProfileReq struct {
	EID         *string `json:"eid"`
	MatchingID  *string `json:"matchingId"`
	SMDSAddress *string `json:"smdsAddress"`
	UPPTemplate *string `json:"uppTemplate"`
	PPRIds      *[]int  `json:"pprIds"`
}

func (h *Handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	p, err := h.Profiles.GetByICCID(iccid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	var req updateProfileReq
	if !readJSON(w, r, &req) {
		return
	}
	if req.EID != nil {
		p.EID = *req.EID
	}
	if req.MatchingID != nil {
		p.MatchingID = *req.MatchingID
	}
	if req.SMDSAddress != nil {
		p.SMDSAddress = *req.SMDSAddress
	}
	if req.UPPTemplate != nil {
		p.UPPTemplate = *req.UPPTemplate
	}
	if req.PPRIds != nil {
		p.PPRIds = rsp.PPRIDBits(*req.PPRIds)
	}
	if err := h.Profiles.Update(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "updateProfile", iccid, "Executed-Success", req)
	writeJSON(w, http.StatusOK, toProfileView(p))
}

func (h *Handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	if err := h.Profiles.Delete(iccid); err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	h.audit(r, "deleteProfile", iccid, "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) confirmProfile(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	var req struct {
		Release          bool   `json:"release"`
		MatchingID       string `json:"matchingId"`
		ConfirmationCode string `json:"confirmationCode"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p, err := h.Profiles.GetByICCID(iccid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	if req.MatchingID != "" {
		p.MatchingID = req.MatchingID
	}
	if req.ConfirmationCode != "" {
		sum := sha256.Sum256([]byte(req.ConfirmationCode))
		p.CCHash, p.CCRequired = sum[:], true
	}
	if err := h.Profiles.Update(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	p, err = h.Orders.Confirm(iccid, req.Release)
	if err != nil {
		h.audit(r, "confirmProfile", iccid, "Failed", req)
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.recordOrder(iccid, p.EID, p.MatchingID, "confirmOrder", req)
	h.audit(r, "confirmProfile", iccid, "Executed-Success", req)
	writeJSON(w, http.StatusOK, toProfileView(p))
}

func (h *Handler) cancelProfile(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	var req struct {
		FinalStatus string `json:"finalStatus"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p, err := h.Orders.Cancel(iccid, strings.EqualFold(req.FinalStatus, "Unavailable"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.recordOrder(iccid, p.EID, p.MatchingID, "cancelOrder", req)
	h.audit(r, "cancelProfile", iccid, "Executed-Success", req)
	writeJSON(w, http.StatusOK, toProfileView(p))
}

func (h *Handler) releaseProfile(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	p, err := h.Orders.Release(iccid)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.recordOrder(iccid, p.EID, p.MatchingID, "releaseProfile", nil)
	h.audit(r, "releaseProfile", iccid, "Executed-Success", nil)
	writeJSON(w, http.StatusOK, toProfileView(p))
}

// profileTimeline merges order-audit rows and received notifications for an
// ICCID into a single (newest-first) event list.
func (h *Handler) profileTimeline(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	type event struct {
		Time    time.Time `json:"time"`
		Kind    string    `json:"kind"` // order | notification
		Action  string    `json:"action"`
		Detail  string    `json:"detail,omitempty"`
		Signed  *bool     `json:"signed,omitempty"`
		Success *bool     `json:"processed,omitempty"`
	}
	var events []event
	if h.OrderRepo != nil {
		orders, err := h.OrderRepo.ListByICCID(iccid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, o := range orders {
			events = append(events, event{Time: o.CreatedAt, Kind: "order", Action: o.Action, Detail: o.MatchingID})
		}
	}
	if h.Notifs != nil {
		notifs, err := h.Notifs.ListByICCID(iccid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
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
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	writeJSON(w, http.StatusOK, map[string]any{"iccid": iccid, "events": events})
}

func (h *Handler) activationCode(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	p, err := h.Profiles.GetByICCID(iccid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	if p.MatchingID == "" {
		writeErr(w, http.StatusBadRequest, "profile has no matchingId; confirm the order first")
		return
	}
	c := &activationcode.Code{FQDN: h.FQDN, MatchingID: p.MatchingID, OID: h.OID, CCRequired: p.CCRequired}
	writeJSON(w, http.StatusOK, map[string]any{
		"matchingId":     p.MatchingID,
		"activationCode": c.String(),
		"qrContent":      c.QRContent(),
	})
}
