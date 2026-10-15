// ES2+.HandleAcrRequest (§5.3.8) and the ACR hook types.

package es2plus

import (
	"encoding/json"
	"net/http"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp/status"
)

func (h *Handler) handleAcrRequest(w http.ResponseWriter, r *http.Request) {
	body, err := common.ReadRaw(w, r, 0)
	if err != nil {
		common.WriteCode(w, status.CodeInputRefused, "cannot read body")
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
		common.WriteCode(w, status.CodeInputRefused, err.Error())
		return
	}
	if resp == nil {
		resp = &AcrResponse{Header: common.NewSuccess()}
	}
	common.WriteJSON(w, resp)
}
