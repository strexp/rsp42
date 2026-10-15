// ES2+.ReleaseProfile (§5.3.5).

package es2plus

import (
	"net/http"

	"rsp42/internal/api/common"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp/status"
	"rsp42/internal/store"
)

func (h *Handler) releaseProfile(w http.ResponseWriter, r *http.Request) {
	var req releaseProfileReq
	hdr, ok := decode(w, r, &req)
	if !ok {
		return
	}
	tenant := h.applyCaller(r, hdr)
	if req.ICCID == "" {
		writeFailure(w, status.CodeMandatoryElementMissing, "iccid is required")
		return
	}
	norm := iccid.Normalize(req.ICCID)
	p, err := h.Profiles.GetByICCID(norm)
	if err != nil {
		writeFailure(w, status.CodeICCIDUnknown, "unknown ICCID")
		return
	}
	if err := h.authorize(tenant, p, ""); err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	// §5.3.4: the Profile must have been processed with DownloadOrder and
	// ConfirmOrder but not released yet. An already-released Profile is the
	// idempotent no-op of the Table 32 NOTE; anything else (Allocated/Linked
	// never confirmed, or already downloaded) is 8.2.1/3.5 Invalid transition.
	switch p.State {
	case store.StateConfirmed, store.StateReleased:
	default:
		writeFailure(w, status.CodeInvalidTransition, "the Profile has not been confirmed, or is already downloaded")
		return
	}
	if _, err := h.Orders.Release(norm); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record(tenant, "releaseProfile", req.ICCID, "", "", req)
	writeSuccess(w, nil)
}
