// Package es9plus implements the SM-DP+ ES9+ handlers (LPA <-> SM-DP+).
package es9plus

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
)

// Handler holds the ES9+ handler dependencies.
type Handler struct {
	Log    *slog.Logger
	CMAE   *service.CMAE
	Notifs *service.NotificationService // optional; wired in Phase 9
}

// New returns a new ES9+ handler.
func New(log *slog.Logger, cmae *service.CMAE) *Handler {
	return &Handler{Log: log, CMAE: cmae}
}

// Mount registers the ES9+ routes on r.
func Mount(r chi.Router, h *Handler) {
	r.Post("/gsma/rsp2/es9plus/initiateAuthentication", h.initiateAuthentication)
	r.Post("/gsma/rsp2/es9plus/authenticateClient", h.authenticateClient)
	r.Post("/gsma/rsp2/es9plus/getBoundProfilePackage", h.getBoundProfilePackage)
	r.Post("/gsma/rsp2/es9plus/handleNotification", h.handleNotification)
	r.Post("/gsma/rsp2/es9plus/cancelSession", h.cancelSession)
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
		common.WriteCode(w, rsp.CodeChallengeInvalid, "invalid request")
		return
	}
	challenge, err := common.DecodeB64(req.EuiccChallenge)
	if err != nil {
		common.WriteCode(w, rsp.CodeChallengeInvalid, "invalid euiccChallenge")
		return
	}
	info, err := common.DecodeB64(req.EuiccInfo1)
	if err != nil {
		common.WriteCode(w, rsp.CodeChallengeInvalid, "invalid euiccInfo1")
		return
	}
	res, err := h.CMAE.Initiate(challenge, info, req.SmdpAddress)
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
		common.WriteCode(w, rsp.CodeVerificationFailed, "invalid request")
		return
	}
	resp, err := common.DecodeB64(req.AuthenticateServerResponse)
	if err != nil {
		common.WriteCode(w, rsp.CodeVerificationFailed, "invalid authenticateServerResponse")
		return
	}
	res, err := h.CMAE.AuthenticateClient(r.Context(), req.TransactionID, resp)
	if err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	if res.ACROnly {
		common.WriteSuccess(w, map[string]any{
			"transactionId":   res.TransactionID,
			"profileMetadata": common.B64(res.ProfileMetadata),
		})
		return
	}
	common.WriteSuccess(w, map[string]any{
		"transactionId":   res.TransactionID,
		"profileMetadata": common.B64(res.ProfileMetadata),
		"smdpSigned2":     common.B64(res.SmdpSigned2),
		"smdpSignature2":  common.B64(res.SmdpSignature2),
		"smdpCertificate": common.B64(res.SmdpCertificate),
	})
}

type getBPPReq struct {
	TransactionID           string `json:"transactionId"`
	PrepareDownloadResponse string `json:"prepareDownloadResponse"`
}

func (h *Handler) getBoundProfilePackage(w http.ResponseWriter, r *http.Request) {
	var req getBPPReq
	if err := common.ReadJSON(w, r, 0, &req); err != nil {
		common.WriteCode(w, rsp.CodeVerificationFailed, "invalid request")
		return
	}
	resp, err := common.DecodeB64(req.PrepareDownloadResponse)
	if err != nil {
		common.WriteCode(w, rsp.CodeVerificationFailed, "invalid prepareDownloadResponse")
		return
	}
	res, err := h.CMAE.GetBoundProfilePackage(req.TransactionID, resp)
	if err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	common.WriteSuccess(w, map[string]any{
		"transactionId":       res.TransactionID,
		"boundProfilePackage": common.B64(res.BoundProfilePackage),
	})
}

type notificationReq struct {
	PendingNotification string `json:"pendingNotification"`
}

func (h *Handler) handleNotification(w http.ResponseWriter, r *http.Request) {
	var req notificationReq
	if err := common.ReadJSON(w, r, 0, &req); err == nil && req.PendingNotification != "" && h.Notifs != nil {
		if raw, err := common.DecodeB64(req.PendingNotification); err == nil {
			_ = h.Notifs.HandlePendingNotification(r.Context(), raw)
		}
	}
	// Notification function: always HTTP 204.
	common.WriteNoContent(w)
}

type cancelReq struct {
	TransactionID         string `json:"transactionId"`
	CancelSessionResponse string `json:"cancelSessionResponse"`
}

func (h *Handler) cancelSession(w http.ResponseWriter, r *http.Request) {
	var req cancelReq
	if err := common.ReadJSON(w, r, 0, &req); err != nil {
		common.WriteCode(w, rsp.CodeUnknownTransaction, "invalid request")
		return
	}
	resp, err := common.DecodeB64(req.CancelSessionResponse)
	if err != nil {
		common.WriteCode(w, rsp.CodeUnknownTransaction, "invalid cancelSessionResponse")
		return
	}
	if _, _, err := h.CMAE.CancelSessionJSON(req.TransactionID, resp); err != nil {
		common.WriteStatusFailure(w, err)
		return
	}
	// The JSON response has no <JSON body> part (SGP.22 §6.5.2.10): the success
	// carries only the functionExecutionStatus header.
	common.WriteSuccess(w, nil)
}
