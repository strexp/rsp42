// ES2+.DownloadOrder (§5.3.1).

package es2plus

import (
	"encoding/json"
	"errors"
	"net/http"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp/status"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

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
			writeFailure(w, status.CodeInvalidRequest, err.Error())
		case errors.Is(err, service.ErrQuotaExceeded):
			writeFailure(w, status.CodeNoMoreProfileAvailable, err.Error())
		case errors.Is(err, service.ErrICCIDInUse):
			writeFailure(w, status.CodeICCIDInUse, err.Error())
		default:
			writeFailure(w, status.CodeAllocateFailed, err.Error())
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
