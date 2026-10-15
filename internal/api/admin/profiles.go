package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"rsp42/internal/activationcode"
	"rsp42/internal/api/adminhttp"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// profileView is the API representation of a profile (no cc_hash or secrets).
type profileView struct {
	ICCID            string     `json:"iccid"`
	Tenant           string     `json:"tenant,omitempty"`
	ExternalRef      string     `json:"externalRef,omitempty"`
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
	BatchID          *int64     `json:"batchId,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	InstalledAt      *time.Time `json:"installedAt,omitempty"`
	ErrorReason      string     `json:"errorReason,omitempty"`
}

func toProfileView(p *store.Profile) profileView {
	v := profileView{
		ICCID: p.ICCID, Tenant: p.TenantID, ExternalRef: p.ExternalRef,
		IMSI: p.IMSI, ProfileType: p.ProfileType, EID: p.EID,
		State: string(p.State), MatchingID: p.MatchingID, CCRequired: p.CCRequired,
		SMDSAddress: p.SMDSAddress, UPPTemplate: p.UPPTemplate,
		DownloadAttempts: p.DownloadAttempts, CCAttempts: p.CCAttempts, BatchID: p.BatchID,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, InstalledAt: p.InstalledAt,
		ErrorReason: p.ErrorReason,
	}
	if len(p.PPRIds) > 0 {
		v.PPRIds = hex.EncodeToString(p.PPRIds)
	}
	return v
}

// profileFilterFromQuery builds a store filter from the shared list query
// parameters.
func profileFilterFromQuery(q map[string][]string) store.ProfileFilter {
	f := store.ProfileFilter{}
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if v, ok := q["tenant"]; ok && len(v) > 0 {
		t := strings.TrimSpace(v[0])
		f.Tenant = &t
	}
	f.ExternalRef = get("externalRef")
	f.State = get("state")
	f.EID = get("eid")
	f.ICCID = get("iccid")
	f.Query = get("q")
	if s := get("batchId"); s != "" {
		if id, err := adminhttp.ParseID(s); err == nil {
			f.BatchID = &id
		}
	}
	if t := adminhttp.ParseTime(get("from")); t != nil {
		f.Since = t
	}
	if t := adminhttp.ParseTime(get("to")); t != nil {
		f.Until = t
	}
	return f
}

func (h *Handler) listProfiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, size := adminhttp.ParsePage(r)
	items, total, err := h.Profiles.ListFiltered(profileFilterFromQuery(q), size, (page-1)*size, q.Get("sort"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]profileView, 0, len(items))
	for _, p := range items {
		views = append(views, toProfileView(p))
	}
	adminhttp.WriteListEnvelope(w, views, page, size, total)
}

func (h *Handler) getProfile(w http.ResponseWriter, r *http.Request) {
	p, err := h.Profiles.GetByICCID(iccid.Normalize(chi.URLParam(r, "iccid")))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	adminhttp.WriteJSON(w, http.StatusOK, toProfileView(p))
}

type createProfileReq struct {
	ICCID       string `json:"iccid"`
	EID         string `json:"eid"`
	ProfileType string `json:"profileType"`
	MatchingID  string `json:"matchingId"`
	SMDSAddress string `json:"smdsAddress"`
	UPPTemplate string `json:"uppTemplate"`
	ExternalRef string `json:"externalRef"`
	Tenant      string `json:"tenant"`
}

func (h *Handler) createProfile(w http.ResponseWriter, r *http.Request) {
	var req createProfileReq
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		h.audit(r, "createProfile", req.ICCID, "Failed", req)
		writeTenantErr(w, err)
		return
	}
	p, err := h.Inventory.Allocate(serviceAllocate(req, tenant))
	if err != nil {
		h.audit(r, "createProfile", req.ICCID, "Failed", req)
		if errors.Is(err, service.ErrQuotaExceeded) {
			writeQuotaErr(w, err)
			return
		}
		if errors.Is(err, service.ErrInvalidICCID) {
			adminhttp.WriteJSON(w, http.StatusBadRequest, adminhttp.ErrorBody("invalid_request", err.Error()))
			return
		}
		adminhttp.WriteErr(w, http.StatusConflict, err.Error())
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
	h.recordOrder(tenant, p.ICCID, p.EID, p.MatchingID, "downloadOrder", req)
	h.audit(r, "createProfile", p.ICCID, "Executed-Success", req)
	adminhttp.WriteJSON(w, http.StatusCreated, toProfileView(p))
}

type updateProfileReq struct {
	EID         *string `json:"eid"`
	Tenant      *string `json:"tenant"`
	ExternalRef *string `json:"externalRef"`
	MatchingID  *string `json:"matchingId"`
	SMDSAddress *string `json:"smdsAddress"`
	UPPTemplate *string `json:"uppTemplate"`
	PPRIds      *[]int  `json:"pprIds"`
}

func (h *Handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	p, err := h.Profiles.GetByICCID(iccid)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	var req updateProfileReq
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	if req.EID != nil {
		p.EID = *req.EID
	}
	if req.Tenant != nil {
		if *req.Tenant != "" && h.Tenants != nil {
			if _, err := h.Tenants.Get(*req.Tenant); err != nil {
				adminhttp.WriteErr(w, http.StatusBadRequest, "unknown tenant "+*req.Tenant)
				return
			}
		}
		p.TenantID = *req.Tenant
	}
	if req.ExternalRef != nil {
		p.ExternalRef = *req.ExternalRef
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
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "updateProfile", iccid, "Executed-Success", req)
	adminhttp.WriteJSON(w, http.StatusOK, toProfileView(p))
}

func (h *Handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	if err := h.Orders.Delete(iccid); err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	h.audit(r, "deleteProfile", iccid, "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) confirmProfile(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	var req struct {
		Release          bool   `json:"release"`
		MatchingID       string `json:"matchingId"`
		ConfirmationCode string `json:"confirmationCode"`
	}
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	p, err := h.Profiles.GetByICCID(iccid)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	if _, err := h.effectiveTenant(r, p.TenantID); err != nil {
		writeTenantErr(w, err)
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
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	p, err = h.Orders.Confirm(iccid, req.Release)
	if err != nil {
		h.audit(r, "confirmProfile", iccid, "Failed", req)
		adminhttp.WriteErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.recordOrder(p.TenantID, iccid, p.EID, p.MatchingID, "confirmOrder", req)
	h.audit(r, "confirmProfile", iccid, "Executed-Success", req)
	adminhttp.WriteJSON(w, http.StatusOK, toProfileView(p))
}

func (h *Handler) cancelProfile(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	var req struct {
		FinalStatus string `json:"finalStatus"`
	}
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	p, err := h.Orders.Cancel(iccid, strings.EqualFold(req.FinalStatus, "Unavailable"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = h.effectiveTenant(r, p.TenantID)
	h.recordOrder(p.TenantID, iccid, p.EID, p.MatchingID, "cancelOrder", req)
	h.audit(r, "cancelProfile", iccid, "Executed-Success", req)
	adminhttp.WriteJSON(w, http.StatusOK, toProfileView(p))
}

func (h *Handler) releaseProfile(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	p, err := h.Orders.Release(iccid)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_, _ = h.effectiveTenant(r, p.TenantID)
	h.recordOrder(p.TenantID, iccid, p.EID, p.MatchingID, "releaseProfile", nil)
	h.audit(r, "releaseProfile", iccid, "Executed-Success", nil)
	adminhttp.WriteJSON(w, http.StatusOK, toProfileView(p))
}

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

// activationCode returns the activation code for a profile, optionally rotating
// the matchingId so previously issued QR codes stop working (G14).
func (h *Handler) activationCode(w http.ResponseWriter, r *http.Request) {
	iccid := iccid.Normalize(chi.URLParam(r, "iccid"))
	p, err := h.Profiles.GetByICCID(iccid)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown ICCID")
		return
	}
	if r.URL.Query().Get("rotate") == "1" {
		p.MatchingID = "MATCH-" + strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", "")[:16])
		if err := h.Profiles.Update(p); err != nil {
			adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		h.audit(r, "rotateActivationCode", iccid, "Executed-Success", nil)
	}
	if p.MatchingID == "" {
		adminhttp.WriteErr(w, http.StatusBadRequest, "profile has no matchingId; confirm the order first")
		return
	}
	c := &activationcode.Code{FQDN: h.FQDN, MatchingID: p.MatchingID, OID: h.OID, CCRequired: p.CCRequired}
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{
		"matchingId":     p.MatchingID,
		"activationCode": c.String(),
		"qrContent":      c.QRContent(),
	})
}
