// Request decoding and the per-action order audit record.

package es2plus

import (
	"encoding/json"
	"net/http"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp/status"
)

// decode reads and validates a request and returns its header. ES2+ requires
// both header identifiers.
func decode(w http.ResponseWriter, r *http.Request, v any) (common.RequestHeader, bool) {
	if err := common.ReadJSON(w, r, 0, v); err != nil {
		common.WriteCode(w, status.CodeInvalidRequest, "invalid JSON")
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
		common.WriteCode(w, status.CodeInvalidRequest, "missing header.functionRequesterIdentifier/functionCallIdentifier")
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
