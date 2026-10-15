// ES2+.CancelOrder (§5.3.3) and its MatchingID/final-status validation.

package es2plus

import (
	"fmt"
	"net/http"
	"strings"

	"rsp42/internal/api/common"
	"rsp42/internal/client/es12"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp/status"
	"rsp42/internal/store"
)

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
		writeFailure(w, status.CodeMandatoryElementMissing, "finalProfileStatusIndicator is required")
		return
	}
	final, err := parseFinalStatus(req.FinalProfileStatusIndicator)
	if err != nil {
		writeFailure(w, status.CodeInvalidRequest, err.Error())
		return
	}
	if req.ICCID == "" {
		writeFailure(w, status.CodeMandatoryElementMissing, "iccid is required")
		return
	}
	if err := h.authorizeICCID(tenant, req.ICCID); err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	norm := iccid.Normalize(req.ICCID)
	p, err := h.Profiles.GetByICCID(norm)
	if err != nil {
		writeFailure(w, status.CodeICCIDUnknown, "unknown ICCID")
		return
	}
	// Table 30: a Profile that is already downloaded is 8.2.1/3.3 (Already in
	// Use); CancelOrder only cancels a pending order.
	if p.State == store.StateDownloaded || p.State == store.StateInstalled {
		writeFailure(w, status.CodeICCIDInUse, "the Profile is already downloaded")
		return
	}
	// Table 30: a supplied MatchingID/EID that is not the one associated with
	// the ICCID is an Invalid Association.
	if req.MatchingID != "" && p.MatchingID != "" && req.MatchingID != p.MatchingID {
		writeFailure(w, status.CodeMatchingIDInvalidAssoc, "a different MatchingID is associated with this ICCID")
		return
	}
	if req.EID != "" && p.EID != "" && req.EID != p.EID {
		writeFailure(w, status.CodeICCIDInvalidAssoc, "a different EID is associated with this ICCID")
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
		meta := es12.EventMeta{Tenant: tenant, ICCID: norm, MatchingID: p.MatchingID}
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
