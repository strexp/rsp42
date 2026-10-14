// Package es2plus implements the SM-DP+ ES2+ server handlers, the outbound
// callback client, and the ES2+ client library used by operator systems.
package es2plus

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"rsp42/internal/api/common"
	"rsp42/internal/api/middleware"
	"rsp42/internal/metrics"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// OrderAuditor records ES2+ order actions.
type OrderAuditor interface {
	Insert(tenant, iccid, eid, matchingID, action, requestJSON, resultJSON string) error
}

// Handler holds the ES2+ handler dependencies.
type Handler struct {
	Log       *slog.Logger
	Profiles  service.ProfileStore
	Orders    *service.OrderService
	Inventory *service.Inventory
	// UPP, when set, is used to validate a "<tenant>/<template>" profileType.
	UPP *store.UPPRepo
	// RequesterTenants maps header.functionRequesterIdentifier to a tenant
	// (decision 3). A nil resolver means "everything is the platform default".
	RequesterTenants *service.TenantResolver
	// Idem, when set, enables Idempotency-Key replay on the write functions
	// whose resend semantics SGP.22 does not define.
	Idem *store.IdempotencyRepo
	// OrderAudit, when set, records each order action.
	OrderAudit OrderAuditor
	// Metrics, when set, counts ES12 registration failures.
	Metrics *metrics.Registry
	// AuditRepo, when set, records ES12 registration failures.
	AuditRepo *store.AuditRepo
	// ACRHandler, when set, is invoked for handleAcrRequest.
	ACRHandler func(req AcrRequest) (*AcrResponse, error)
	// Registrar, when set, registers an SM-DS event on ConfirmOrder.
	Registrar *service.Registrar
}

// New returns a new ES2+ handler.
func New(log *slog.Logger, profiles service.ProfileStore, orders *service.OrderService, inv *service.Inventory) *Handler {
	return &Handler{Log: log, Profiles: profiles, Orders: orders, Inventory: inv}
}

// Mount registers the ES2+ routes on r.
func Mount(r chi.Router, h *Handler) {
	idem := middleware.Idempotency(h.Idem)
	r.Post("/gsma/rsp2/es2plus/downloadOrder", h.downloadOrder)
	r.With(idem).Post("/gsma/rsp2/es2plus/confirmOrder", h.confirmOrder)
	r.With(idem).Post("/gsma/rsp2/es2plus/cancelOrder", h.cancelOrder)
	r.With(idem).Post("/gsma/rsp2/es2plus/releaseProfile", h.releaseProfile)
	r.Post("/gsma/rsp2/es2plus/handleDownloadProgressInfo", h.handleDownloadProgressInfo)
	r.Post("/gsma/rsp2/es2plus/handleAcrRequest", h.handleAcrRequest)
}

// Request types -------------------------------------------------------------

type downloadOrderReq struct {
	Header      common.RequestHeader `json:"header"`
	EID         string               `json:"eid"`
	ICCID       string               `json:"iccid"`
	ProfileType string               `json:"profileType"`
}

type confirmOrderReq struct {
	Header           common.RequestHeader `json:"header"`
	ICCID            string               `json:"iccid"`
	EID              string               `json:"eid"`
	MatchingID       string               `json:"matchingId"`
	ConfirmationCode string               `json:"confirmationCode"`
	SMDSAddress      string               `json:"smdsAddress"`
	ReleaseFlag      bool                 `json:"releaseFlag"`
}

type cancelOrderReq struct {
	Header                      common.RequestHeader `json:"header"`
	ICCID                       string               `json:"iccid"`
	EID                         string               `json:"eid"`
	MatchingID                  string               `json:"matchingId"`
	FinalProfileStatusIndicator string               `json:"finalProfileStatusIndicator"`
}

type releaseProfileReq struct {
	Header common.RequestHeader `json:"header"`
	ICCID  string               `json:"iccid"`
}

// AcrRequest / AcrResponse are the confirm/ACR hooks (Phase 10 supplies these).
type AcrRequest struct {
	EID   string          `json:"eid"`
	ICCID string          `json:"iccid"`
	Data  json.RawMessage `json:"-"`
}

// AcrResponse is the operator's response to handleAcrRequest.
type AcrResponse struct {
	Header common.HeaderResponse `json:"header"`
}

// Handlers ------------------------------------------------------------------

func (h *Handler) downloadOrder(w http.ResponseWriter, r *http.Request) {
	var req downloadOrderReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	template, parsed, err := h.resolveProfileType(tenant, req.ProfileType)
	if err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	// C2: a profileType without the "<tenant>/<template>" selector no longer
	// degrades silently; the outcome is recorded once the ICCID is known so an
	// operator typo shows up as such rather than as "the wrong template was
	// downloaded".
	unparsed := !parsed && req.ProfileType != ""
	p, err := h.Inventory.Allocate(service.AllocateRequest{
		EID:         req.EID,
		ProfileType: req.ProfileType,
		ICCID:       req.ICCID,
		UPPTemplate: template,
		Tenant:      tenant,
		Reference:   hdr.FunctionCallIdentifier,
	})
	if err != nil {
		// C3: distinguish "no Profile of this type is available" (8.2.5/3.7)
		// from "this ICCID cannot be issued" (8.2.1/3.3) and a generic
		// allocation failure (8.2/4.2).
		switch {
		case errors.Is(err, service.ErrQuotaExceeded):
			writeFailure(w, rsp.CodeNoMoreProfileAvailable, err.Error())
		case errors.Is(err, service.ErrICCIDInUse):
			writeFailure(w, rsp.CodeICCIDInUse, err.Error())
		default:
			writeFailure(w, rsp.CodeAllocateFailed, err.Error())
		}
		return
	}
	if unparsed {
		if h.Metrics != nil {
			h.Metrics.Inc("rsp42_es2p_profile_type_unparsed_total", map[string]string{"tenant": tenant})
		}
		if h.AuditRepo != nil {
			detail, _ := json.Marshal(map[string]string{"profileType": req.ProfileType, "warning": "profileType-unparsed"})
			_ = h.AuditRepo.Insert(&store.AuditEntry{
				TenantID: tenant, Interface: "es2p", Function: "downloadOrder",
				Subject: p.ICCID, Outcome: "Executed-Success", DetailJSON: string(detail),
			})
		}
	}
	if err := h.record(tenant, "downloadOrder", req.ICCID, req.EID, "", req); err != nil {
		h.Log.Warn("order record", "err", err)
	}
	writeSuccess(w, map[string]any{"iccid": p.ICCID})
}

func (h *Handler) confirmOrder(w http.ResponseWriter, r *http.Request) {
	var req confirmOrderReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	if req.ICCID == "" {
		writeFailure(w, rsp.CodeMandatoryElementMissing, "iccid is required")
		return
	}
	p, err := h.Profiles.GetByICCID(normalizeICCID(req.ICCID))
	if err != nil {
		writeFailure(w, rsp.CodeICCIDUnknown, "unknown ICCID")
		return
	}
	if err := h.authorize(tenant, p, req.EID); err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	if req.EID != "" {
		p.EID = req.EID
	}
	matchingID := req.MatchingID
	if matchingID == "" {
		matchingID = "MATCH-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	}
	p.MatchingID = matchingID
	if req.SMDSAddress != "" {
		p.SMDSAddress = req.SMDSAddress
	}
	if req.ConfirmationCode != "" {
		sum := sha256.Sum256([]byte(req.ConfirmationCode))
		p.CCHash = sum[:]
		p.CCRequired = true
	}
	if err := h.Profiles.Update(p); err != nil {
		writeFailure(w, rsp.CodeProfileUpdateFailed, err.Error())
		return
	}
	if _, err := h.Orders.Confirm(p.ICCID, req.ReleaseFlag); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record(tenant, "confirmOrder", p.ICCID, p.EID, matchingID, req)
	if req.SMDSAddress != "" && h.Registrar != nil && p.EID != "" {
		meta := service.EventMeta{Tenant: tenant, ICCID: p.ICCID, MatchingID: matchingID}
		if err := h.Registrar.Register(p.EID, matchingID, req.SMDSAddress, meta); err != nil {
			h.Log.Warn("ES12 register event", "eid", p.EID, "tenant", tenant, "err", err)
			h.registerFailure(tenant, p.EID, p.ICCID, err)
		}
	}
	writeSuccess(w, map[string]any{"matchingId": matchingID, "smdpAddress": ""})
}

func (h *Handler) cancelOrder(w http.ResponseWriter, r *http.Request) {
	var req cancelOrderReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	final, err := parseFinalStatus(req.FinalProfileStatusIndicator)
	if err != nil {
		writeFailure(w, rsp.CodeInputRefused, err.Error())
		return
	}
	if req.ICCID == "" {
		writeFailure(w, rsp.CodeMandatoryElementMissing, "iccid is required")
		return
	}
	if err := h.authorizeICCID(tenant, req.ICCID); err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	if _, err := h.Orders.Cancel(normalizeICCID(req.ICCID), final == finalUnavailable); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record(tenant, "cancelOrder", req.ICCID, req.EID, req.MatchingID, req)
	writeSuccess(w, nil)
}

// finalProfileStatusIndicator values (SGP.22 Table 29).
const (
	finalAvailable   = "Available"
	finalUnavailable = "Unavailable"
)

// parseFinalStatus maps the ES2+ finalProfileStatusIndicator to its canonical
// form. Table 29 defines exactly two values; a missing or unknown value is
// refused (CancelOrder is specified to return Failed with a relevant status
// code, e.g. 8.2.1/1.2).
func parseFinalStatus(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "available":
		return finalAvailable, nil
	case "unavailable":
		return finalUnavailable, nil
	default:
		return "", fmt.Errorf("invalid finalProfileStatusIndicator %q (want Available|Unavailable)", s)
	}
}

func (h *Handler) releaseProfile(w http.ResponseWriter, r *http.Request) {
	var req releaseProfileReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	if req.ICCID == "" {
		writeFailure(w, rsp.CodeMandatoryElementMissing, "iccid is required")
		return
	}
	if err := h.authorizeICCID(tenant, req.ICCID); err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	if _, err := h.Orders.Release(normalizeICCID(req.ICCID)); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record(tenant, "releaseProfile", req.ICCID, "", "", req)
	writeSuccess(w, nil)
}

func (h *Handler) handleDownloadProgressInfo(w http.ResponseWriter, _ *http.Request) {
	// Notification function: always HTTP 204.
	common.WriteNoContent(w)
}

func (h *Handler) handleAcrRequest(w http.ResponseWriter, r *http.Request) {
	body, err := common.ReadRaw(w, r, 1<<20)
	if err != nil {
		common.WriteCode(w, rsp.CodeInputRefused, "cannot read body")
		return
	}
	if h.ACRHandler == nil {
		http.Error(w, "handleAcrRequest not implemented", http.StatusNotImplemented)
		return
	}
	var req AcrRequest
	_ = json.Unmarshal(body, &req)
	req.Data = body
	resp, err := h.ACRHandler(req)
	if err != nil {
		common.WriteCode(w, rsp.CodeInputRefused, err.Error())
		return
	}
	if resp == nil {
		resp = &AcrResponse{Header: common.NewSuccess()}
	}
	common.WriteJSON(w, resp)
}

// Tenant / authorisation ----------------------------------------------------

// applyCaller records the caller identity in the audit scope and resolves the
// tenant from functionRequesterIdentifier.
func (h *Handler) applyCaller(r *http.Request, hdr common.RequestHeader) string {
	common.SetActor(r.Context(), hdr.FunctionRequesterIdentifier)
	tenant, mapped := h.RequesterTenants.Resolve(hdr.FunctionRequesterIdentifier)
	if !mapped {
		tenant = ""
		if h.RequesterTenants.Len() > 0 && h.Log != nil {
			h.Log.Warn("unmapped ES2+ functionRequesterIdentifier; using the platform default tenant",
				"requester", hdr.FunctionRequesterIdentifier)
		}
	}
	common.SetTenant(r.Context(), tenant)
	return tenant
}

// resolveProfileType interprets the operator's profileType. A
// "<tenant>/<template>" value selects a template inside the caller's tenant
// (SGP.22 §6.5.2.1: profileType is content free information defined by the
// Operator). The second return value reports whether the value carried the
// selector; anything else stays opaque and lets the SM-DP+ fall back to the
// eUICC version and the tenant default, but the caller records it (C2).
func (h *Handler) resolveProfileType(tenant, profileType string) (string, bool, error) {
	i := strings.IndexByte(profileType, '/')
	if i < 0 {
		return "", false, nil
	}
	want, name := profileType[:i], profileType[i+1:]
	if want == "" || name == "" {
		return "", false, rsp.CodeProfileTypeUnknown.Status("malformed profileType " + profileType)
	}
	if want != tenant {
		return "", false, rsp.CodeProfileTypeNotAllowed.Status("profileType belongs to another tenant")
	}
	if h.UPP != nil {
		if _, err := h.UPP.GetForTenant(tenant, name); err != nil {
			return "", false, rsp.CodeProfileTypeUnknown.Status("unknown profileType template " + name)
		}
	}
	return name, true, nil
}

// authorize enforces tenant ownership of a profile and, when the request
// carries an EID, the EID consistency required by SGP.22 §5.3.2.
func (h *Handler) authorize(tenant string, p *store.Profile, eid string) error {
	if p.TenantID != tenant {
		return rsp.CodeInputRefused.Status("ICCID belongs to another tenant")
	}
	if eid != "" && p.EID != "" && p.EID != eid {
		return rsp.CodeInvalidAssociation.Status("eid does not match the download order")
	}
	return nil
}

// authorizeICCID loads a profile and enforces tenant ownership. An unknown
// ICCID is reported as such (8.2.1/3.9), distinct from an authorisation
// failure (8.2.1/1.2).
func (h *Handler) authorizeICCID(tenant, iccid string) error {
	p, err := h.Profiles.GetByICCID(normalizeICCID(iccid))
	if err != nil {
		return rsp.CodeICCIDUnknown.Status("unknown ICCID")
	}
	if p.TenantID != tenant {
		return rsp.CodeInputRefused.Status("ICCID belongs to another tenant")
	}
	return nil
}

// registerFailure makes an ES12 registration failure observable: esim42 needs
// to know that an event was not registered (G20), so it is counted and audited
// rather than only logged.
func (h *Handler) registerFailure(tenant, eid, iccid string, err error) {
	if h.Metrics != nil {
		h.Metrics.Inc("rsp42_es12_register_failures_total", map[string]string{"tenant": tenant})
	}
	if h.AuditRepo == nil {
		return
	}
	detail, _ := json.Marshal(map[string]string{"eid": eid, "iccid": iccid, "error": err.Error()})
	_ = h.AuditRepo.Insert(&store.AuditEntry{
		TenantID: tenant, Interface: "es12", Function: "registerEvent", Subject: eid,
		Outcome: "Failed", DetailJSON: string(detail),
	})
}

// Helpers -------------------------------------------------------------------

// decode reads and validates a request and returns its header. ES2+ requires
// both header identifiers.
func decode(w http.ResponseWriter, r *http.Request, v any) (common.RequestHeader, bool) {
	if err := common.ReadJSON(w, r, 1<<20, v); err != nil {
		common.WriteCode(w, rsp.CodeInvalidRequest, "invalid JSON")
		return common.RequestHeader{}, false
	}
	var hdr common.RequestHeader
	switch t := v.(type) {
	case *downloadOrderReq:
		hdr = t.Header
	case *confirmOrderReq:
		hdr = t.Header
	case *cancelOrderReq:
		hdr = t.Header
	case *releaseProfileReq:
		hdr = t.Header
	}
	if hdr.FunctionRequesterIdentifier == "" || hdr.FunctionCallIdentifier == "" {
		common.WriteCode(w, rsp.CodeInvalidRequest, "missing header.functionRequesterIdentifier/functionCallIdentifier")
		return common.RequestHeader{}, false
	}
	return hdr, true
}

func (h *Handler) record(tenant, action, iccid, eid, matchingID string, req any) error {
	if h.OrderAudit == nil {
		return nil
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return h.OrderAudit.Insert(tenant, iccid, eid, matchingID, action, string(raw), "")
}

func writeSuccess(w http.ResponseWriter, extra map[string]any) {
	common.WriteSuccess(w, extra)
}

func writeFailure(w http.ResponseWriter, code rsp.Code, message string) {
	common.WriteCode(w, code, message)
}

func writeError(w http.ResponseWriter, err error) {
	var te *service.TransitionError
	if errors.As(err, &te) {
		common.WriteCode(w, rsp.CodeInvalidTransition, err.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		common.WriteCode(w, rsp.CodeICCIDUnknown, "unknown ICCID")
		return
	}
	common.WriteStatusFailure(w, err)
}

// normalizeICCID strips a trailing F padding so DB lookups match 19/20-digit
// inputs.
func normalizeICCID(iccid string) string {
	return strings.TrimRight(iccid, "fF")
}
