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
	"rsp42/internal/iccid"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// OrderAuditor records ES2+ order actions.
type OrderAuditor interface {
	Insert(tenant, iccid, eid, matchingID, action, requestJSON, resultJSON string) error
}

// AuditWriter records protocol-level ES2+ failures (ES2+ answers HTTP 200 with a
// Failed status for some functions, so the audit middleware cannot see them).
type AuditWriter interface {
	Insert(e *store.AuditEntry) error
}

// UPPValidator checks that a "<tenant>/<template>" profileType resolves to a
// registered template. It is defined here so the handler does not depend on the
// concrete SQLite repository.
type UPPValidator interface {
	GetForTenant(tenant, name string) (*store.UPPTemplate, error)
}

// MetricCounter counts interface-level events. It is the subset of
// *metrics.Registry the ES2+ handler uses.
type MetricCounter interface {
	Inc(name string, labels map[string]string)
}

// Deps is the complete ES2+ handler dependency set, so the handler cannot be
// constructed half-wired. The two late-bound hooks stay out of it on purpose:
//
//   - Registrar registers SM-DS events and is installed once the ES12 client
//     exists (its construction needs the SM-DP+ identity, not this handler);
//   - ACRHandler serves the inbound handleAcrRequest stub and is unused by
//     rsp42 itself (ACR is performed outbound).
type Deps struct {
	Log       *slog.Logger
	Profiles  service.ProfileStore
	Orders    *service.OrderService
	Inventory *service.Inventory
	// UPP validates a "<tenant>/<template>" profileType.
	UPP UPPValidator
	// RequesterTenants maps header.functionRequesterIdentifier to a tenant
	// (decision 3). A nil resolver means "everything is the platform default".
	RequesterTenants *service.TenantResolver
	// Idem, when set, enables Idempotency-Key replay on the write functions
	// whose resend semantics SGP.22 does not define.
	Idem middleware.IdempotencyStore
	// OrderAudit, when set, records each order action.
	OrderAudit OrderAuditor
	// Metrics, when set, counts ES12 registration failures.
	Metrics MetricCounter
	// AuditRepo, when set, records ES12 registration failures.
	AuditRepo AuditWriter
}

// Handler serves the ES2+ interface.
type Handler struct {
	Deps
	// ACRHandler, when set, is invoked for handleAcrRequest.
	ACRHandler func(req AcrRequest) (*AcrResponse, error)
	// Registrar, when set, registers an SM-DS event on ConfirmOrder.
	Registrar *service.Registrar
}

// New returns a new ES2+ handler with its dependencies wired.
func New(d Deps) *Handler { return &Handler{Deps: d} }

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
		case errors.Is(err, service.ErrInvalidICCID):
			writeFailure(w, rsp.CodeInvalidRequest, err.Error())
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
	p, err := h.Profiles.GetByICCID(iccid.Normalize(req.ICCID))
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
	// Table 27: the EID is mandatory in the context of this order when an SM-DS
	// address is provided (the event registration is keyed by the EID). A
	// Profile that is already bound carries its EID, so this only rejects an
	// anonymous order that asks for an SM-DS event.
	if req.SMDSAddress != "" && p.EID == "" {
		writeFailure(w, rsp.CodeMandatoryElementMissing, "eid is required when smdsAddress is provided")
		return
	}
	// §4.1.1: a MatchingID consists only of upper case alphanumeric characters
	// and '-'. An empty value means "generate one"; anything else is malformed.
	if req.MatchingID != "" && !validMatchingID(req.MatchingID) {
		writeFailure(w, rsp.CodeInvalidRequest, "matchingId must be upper case alphanumeric or '-'")
		return
	}
	matchingID := req.MatchingID
	if matchingID == "" {
		matchingID = "MATCH-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	}
	// The SM-DS registration is keyed by the MatchingID (§3.6). Re-confirming an
	// order with a different one leaves a registration that no longer matches the
	// Profile - an LPA could still discover it, but the Activation Code would be
	// refused - so the previous registration is dropped first.
	previousMatchingID := p.MatchingID
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
		// Table 27: a MatchingID that another order already uses is 8.2.6/3.3.
		// The unique index is the authority (a pre-check would race), and the
		// store error itself must not reach the caller.
		if store.IsUniqueViolation(err) {
			writeFailure(w, rsp.CodeMatchingIDInUse, "matchingId is already in use")
			return
		}
		h.Log.Warn("confirmOrder profile update", "iccid", p.ICCID, "err", err)
		writeFailure(w, rsp.CodeProfileUpdateFailed, "the Profile could not be updated")
		return
	}
	if _, err := h.Orders.Confirm(p.ICCID, req.ReleaseFlag); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record(tenant, "confirmOrder", p.ICCID, p.EID, matchingID, req)
	// A registration for the order's previous MatchingID is stale now.
	if previousMatchingID != "" && previousMatchingID != matchingID && h.Registrar != nil && p.EID != "" {
		meta := service.EventMeta{Tenant: tenant, ICCID: p.ICCID, MatchingID: previousMatchingID}
		if err := h.Registrar.DeleteEvent(p.EID, previousMatchingID, meta); err != nil {
			h.Log.Warn("ES12 delete stale event after a MatchingID change",
				"eid", p.EID, "eventId", previousMatchingID, "tenant", tenant, "err", err)
		}
	}
	if req.SMDSAddress != "" && h.Registrar != nil && p.EID != "" {
		meta := service.EventMeta{Tenant: tenant, ICCID: p.ICCID, MatchingID: matchingID}
		if err := h.Registrar.Register(p.EID, matchingID, req.SMDSAddress, meta); err != nil {
			h.Log.Warn("ES12 register event", "eid", p.EID, "tenant", tenant, "err", err)
		}
	}
	writeSuccess(w, map[string]any{"matchingId": matchingID, "smdpAddress": ""})
}

// cancelOrder implements ES2+.CancelOrder (§5.3.3). The function SHALL verify
// that the Profile is still a pending order (allocated, not yet downloaded) and
// that any supplied MatchingID/EID matches the order, and SHALL then delete the
// SM-DS event registration of a cancelled order. Table 30 defines the codes for
// each verification failure.
func (h *Handler) cancelOrder(w http.ResponseWriter, r *http.Request) {
	var req cancelOrderReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	// finalProfileStatusIndicator is mandatory (Table 28): an absent element and
	// an unrecognised value are different failures.
	if strings.TrimSpace(req.FinalProfileStatusIndicator) == "" {
		writeFailure(w, rsp.CodeMandatoryElementMissing, "finalProfileStatusIndicator is required")
		return
	}
	final, err := parseFinalStatus(req.FinalProfileStatusIndicator)
	if err != nil {
		writeFailure(w, rsp.CodeInvalidRequest, err.Error())
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
	norm := iccid.Normalize(req.ICCID)
	p, err := h.Profiles.GetByICCID(norm)
	if err != nil {
		writeFailure(w, rsp.CodeICCIDUnknown, "unknown ICCID")
		return
	}
	// Table 30: a Profile that is already downloaded is 8.2.1/3.3 (Already in
	// Use); CancelOrder only cancels a pending order.
	if p.State == store.StateDownloaded || p.State == store.StateInstalled {
		writeFailure(w, rsp.CodeICCIDInUse, "the Profile is already downloaded")
		return
	}
	// Table 30: a supplied MatchingID/EID that is not the one associated with
	// the ICCID is an Invalid Association.
	if req.MatchingID != "" && p.MatchingID != "" && req.MatchingID != p.MatchingID {
		writeFailure(w, rsp.CodeMatchingIDInvalidAssoc, "a different MatchingID is associated with this ICCID")
		return
	}
	if req.EID != "" && p.EID != "" && req.EID != p.EID {
		writeFailure(w, rsp.CodeICCIDInvalidAssoc, "a different EID is associated with this ICCID")
		return
	}
	if _, err := h.Orders.Cancel(norm, final == finalUnavailable); err != nil {
		writeError(w, err)
		return
	}
	// §5.3.3: if the order had been linked to an event registration, the SM-DP+
	// SHALL delete it. A failure here must not fail the cancel (the order is
	// already cancelled); it is logged, and the ES12 failure metric covers it.
	if p.EID != "" && h.Registrar != nil {
		meta := service.EventMeta{Tenant: tenant, ICCID: norm, MatchingID: p.MatchingID}
		if err := h.Registrar.DeleteForEID(p.EID, meta); err != nil {
			h.Log.Warn("ES12 delete event after cancelOrder", "eid", p.EID, "tenant", tenant, "err", err)
		}
	}
	_ = h.record(tenant, "cancelOrder", req.ICCID, req.EID, req.MatchingID, req)
	writeSuccess(w, nil)
}

// validMatchingID enforces the MatchingID character set of SGP.22 §4.1.1: upper
// case alphanumeric characters (0-9, A-Z) and '-'. An empty value is allowed and
// means "let the SM-DP+ generate one".
func validMatchingID(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z', c == '-':
		default:
			return false
		}
	}
	return true
}

// finalProfileStatusIndicator values (SGP.22 Table 29).
const (
	finalAvailable   = "Available"
	finalUnavailable = "Unavailable"
)

// parseFinalStatus maps the ES2+ finalProfileStatusIndicator to its canonical
// form. Table 29 defines exactly two values (Available, Unavailable); anything
// else is a malformed request. The caller checks absence separately, because a
// missing mandatory element is 8.1.1/2.2 while an unknown value is not.
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
	if _, err := h.Orders.Release(iccid.Normalize(req.ICCID)); err != nil {
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
	body, err := common.ReadRaw(w, r, 0)
	if err != nil {
		common.WriteCode(w, rsp.CodeInputRefused, "cannot read body")
		return
	}
	if h.ACRHandler == nil {
		// The inbound function is a reserved stub: rsp42 itself performs ACR
		// outgoing (service.ACRChecker), and nothing wires ACRHandler yet. Answer
		// a JSON HTTP-level error rather than a plain-text body so a JSON client
		// can still parse it.
		common.WriteHTTPError(w, http.StatusNotImplemented, "handleAcrRequest is not configured")
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
//
// An unmapped requester falls back to the platform-default tenant (""), and the
// fallback is recorded on the audit row (`warning=unmapped`, plus the requester
// and the resolved tenant) and counted in
// rsp42_es2p_tenant_unmapped_total, so an operator health check can alert on a
// carrier that was never registered (docs/esim42-integration-gaps.md §2.3). With
// an empty requester_tenants table nothing is flagged: a single-tenant
// deployment has nothing to map.
func (h *Handler) applyCaller(r *http.Request, hdr common.RequestHeader) string {
	ctx := r.Context()
	common.SetActor(ctx, hdr.FunctionRequesterIdentifier)
	tenant, mapped := h.RequesterTenants.Resolve(hdr.FunctionRequesterIdentifier)
	if !mapped {
		tenant = ""
		if h.RequesterTenants.Len() > 0 {
			common.AddDetail(ctx, "warning", "unmapped")
			common.AddDetail(ctx, "requester", hdr.FunctionRequesterIdentifier)
			if h.Metrics != nil {
				h.Metrics.Inc("rsp42_es2p_tenant_unmapped_total", nil)
			}
			if h.Log != nil {
				h.Log.Warn("unmapped ES2+ functionRequesterIdentifier; using the platform default tenant",
					"requester", hdr.FunctionRequesterIdentifier)
			}
		}
	}
	common.SetTenant(ctx, tenant)
	return tenant
}

// resolveProfileType interprets the operator's profileType. A
// "<tenant>/<template>" value selects a template inside the caller's tenant
// (SGP.22 §6.5.2.1: profileType is content free information defined by the
// Operator). The second return value reports whether the value carried the
// selector; anything else stays opaque and lets the SM-DP+ fall back to the
// eUICC version and the tenant default, but the caller records it (C2).
//
// An empty tenant part ("/<template>") names a template owned by the
// platform-default tenant, i.e. a global template (including one promoted with
// POST /upp/{name}/promote). That is the only way to select such a template: a
// caller mapped to a carrier has no prefix that denotes the platform-default
// owner. The name is still resolved with the caller's scope, so a tenant only
// ever reaches its own template or a global one.
func (h *Handler) resolveProfileType(tenant, profileType string) (string, bool, error) {
	i := strings.IndexByte(profileType, '/')
	if i < 0 {
		return "", false, nil
	}
	want, name := profileType[:i], profileType[i+1:]
	if name == "" {
		return "", false, rsp.CodeProfileTypeUnknown.Status("malformed profileType " + profileType)
	}
	if want != "" && want != tenant {
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
func (h *Handler) authorizeICCID(tenant, rawICCID string) error {
	p, err := h.Profiles.GetByICCID(iccid.Normalize(rawICCID))
	if err != nil {
		return rsp.CodeICCIDUnknown.Status("unknown ICCID")
	}
	if p.TenantID != tenant {
		return rsp.CodeInputRefused.Status("ICCID belongs to another tenant")
	}
	return nil
}

// Helpers -------------------------------------------------------------------

// decode reads and validates a request and returns its header. ES2+ requires
// both header identifiers.
func decode(w http.ResponseWriter, r *http.Request, v any) (common.RequestHeader, bool) {
	if err := common.ReadJSON(w, r, 0, v); err != nil {
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
