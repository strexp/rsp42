// Package es11 implements the SM-DS ES11 handlers (LPA <-> SM-DS).
//
// ES11 reuses the ES9+ path semantics on the SM-DS FQDN (SGP.22 Table 57
// "[As ES9+]"), so these routes mirror the ES9+ ones.
package es11

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
)

// Handler holds the ES11 handler dependencies.
type Handler struct {
	Log *slog.Logger
	DS  *service.DSService
}

// New returns a new ES11 handler.
func New(log *slog.Logger, ds *service.DSService) *Handler { return &Handler{Log: log, DS: ds} }

// Mount registers the ES11 routes on r.
func Mount(r chi.Router, h *Handler) {
	r.Post("/gsma/rsp2/es9plus/initiateAuthentication", h.initiateAuthentication)
	r.Post("/gsma/rsp2/es9plus/authenticateClient", h.authenticateClient)
	// ASN.1 binding (SGP.22 §6.6): all functions use the generic path.
	r.Post("/gsma/rsp2/asn1", h.asn1Binding)
}

type initiateReq struct {
	EuiccChallenge string `json:"euiccChallenge"`
	EuiccInfo1     string `json:"euiccInfo1"`
	SmdpAddress    string `json:"smdpAddress"`
}

func (h *Handler) initiateAuthentication(w http.ResponseWriter, r *http.Request) {
	var req initiateReq
	if err := common.ReadJSON(w, r, 0, &req); err != nil {
		common.WriteCode(w, rsp.CodeDSAddress, "invalid request")
		return
	}
	challenge, err := common.DecodeB64(req.EuiccChallenge)
	if err != nil {
		common.WriteCode(w, rsp.CodeDSAddress, "invalid euiccChallenge")
		return
	}
	info, err := common.DecodeB64(req.EuiccInfo1)
	if err != nil {
		common.WriteCode(w, rsp.CodeDSAddress, "invalid euiccInfo1")
		return
	}
	res, err := h.DS.Initiate(challenge, info, req.SmdpAddress)
	if err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	common.WriteSuccess(w, map[string]any{
		"transactionId":       res.TransactionID,
		"serverSigned1":       common.B64(res.ServerSigned1),
		"serverSignature1":    common.B64(res.ServerSignature1),
		"euiccCiPKIdToBeUsed": common.B64(res.EuiccCiPKIDToBeUsed),
		"serverCertificate":   common.B64(res.ServerCertificate),
	})
}

type authenticateReq struct {
	TransactionID              string `json:"transactionId"`
	AuthenticateServerResponse string `json:"authenticateServerResponse"`
}

func (h *Handler) authenticateClient(w http.ResponseWriter, r *http.Request) {
	var req authenticateReq
	if err := common.ReadJSON(w, r, 0, &req); err != nil {
		common.WriteCode(w, rsp.CodeDSAuthFailed, "invalid request")
		return
	}
	resp, err := common.DecodeB64(req.AuthenticateServerResponse)
	if err != nil {
		common.WriteCode(w, rsp.CodeDSAuthFailed, "invalid authenticateServerResponse")
		return
	}
	res, err := h.DS.AuthenticateClient(req.TransactionID, resp)
	if err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	entries := make([]map[string]string, 0, len(res.EventEntries))
	for _, e := range res.EventEntries {
		entries = append(entries, map[string]string{"eventId": e[0], "rspServerAddress": e[1]})
	}
	common.WriteSuccess(w, map[string]any{
		"transactionId": res.TransactionID,
		"eventEntries":  entries,
	})
}
