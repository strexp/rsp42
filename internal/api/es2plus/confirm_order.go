// ES2+.ConfirmOrder (§5.3.2).

package es2plus

import (
	"crypto/sha256"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"rsp42/internal/api/common"
	"rsp42/internal/client/es12"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp/status"
	"rsp42/internal/store"
)

func (h *Handler) confirmOrder(w http.ResponseWriter, r *http.Request) {
	var req confirmOrderReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	if req.ICCID == "" {
		writeFailure(w, status.CodeMandatoryElementMissing, "iccid is required")
		return
	}
	if req.ReleaseFlag == nil {
		writeFailure(w, status.CodeMandatoryElementMissing, "releaseFlag is required")
		return
	}
	release := *req.ReleaseFlag
	p, err := h.Profiles.GetByICCID(iccid.Normalize(req.ICCID))
	if err != nil {
		writeFailure(w, status.CodeICCIDUnknown, "unknown ICCID")
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
		writeFailure(w, status.CodeMandatoryElementMissing, "eid is required when smdsAddress is provided")
		return
	}
	// §4.1.1: a MatchingID consists only of upper case alphanumeric characters
	// and '-'. An empty value means "generate one"; anything else is malformed.
	if req.MatchingID != "" && !validMatchingID(req.MatchingID) {
		writeFailure(w, status.CodeInvalidRequest, "matchingId must be upper case alphanumeric or '-'")
		return
	}
	matchingID := req.MatchingID
	if matchingID == "" {
		// §4.1.1: a MatchingID is upper case alphanumeric plus '-' only, so the
		// generated token must be upper-cased (google/uuid emits lower-case hex).
		matchingID = "MATCH-" + strings.ToUpper(strings.ReplaceAll(uuid.NewString(), "-", "")[:16])
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
			writeFailure(w, status.CodeMatchingIDInUse, "matchingId is already in use")
			return
		}
		h.Log.Warn("confirmOrder profile update", "iccid", p.ICCID, "err", err)
		writeFailure(w, status.CodeProfileUpdateFailed, "the Profile could not be updated")
		return
	}
	if _, err := h.Orders.Confirm(p.ICCID, release); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record(tenant, "confirmOrder", p.ICCID, p.EID, matchingID, req)
	// A registration for the order's previous MatchingID is stale now.
	if previousMatchingID != "" && previousMatchingID != matchingID && h.Registrar != nil && p.EID != "" {
		meta := es12.EventMeta{Tenant: tenant, ICCID: p.ICCID, MatchingID: previousMatchingID}
		if err := h.Registrar.DeleteEvent(p.EID, previousMatchingID, meta); err != nil {
			h.Log.Warn("ES12 delete stale event after a MatchingID change",
				"eid", p.EID, "eventId", previousMatchingID, "tenant", tenant, "err", err)
		}
	}
	if req.SMDSAddress != "" && h.Registrar != nil && p.EID != "" {
		meta := es12.EventMeta{Tenant: tenant, ICCID: p.ICCID, MatchingID: matchingID}
		if err := h.Registrar.Register(p.EID, matchingID, req.SMDSAddress, meta); err != nil {
			h.Log.Warn("ES12 register event", "eid", p.EID, "tenant", tenant, "err", err)
		}
	}
	// Table 26: `smdpAddress` is the SM-DP+ address to use for this specific
	// download order. It is optional, but when the deployment knows its own
	// FQDN there is no reason to withhold it: without it an operator has to
	// configure the address out of band to build an Activation Code.
	extra := map[string]any{"matchingId": matchingID}
	if h.FQDN != "" {
		extra["smdpAddress"] = h.FQDN
	}
	// Table 26: the EID SHALL be returned when it is bound to this order.
	if p.EID != "" {
		extra["eid"] = p.EID
	}
	writeSuccess(w, extra)
}
