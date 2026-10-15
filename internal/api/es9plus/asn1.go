package es9plus

import (
	"context"
	"encoding/hex"
	"net/http"

	"rsp42/internal/api/asn1bind"
	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
)

// ES9+ ASN.1 error codes. The numeric space is SGP.22 §6.6's
// InitiateAuthenticationResponseError / AuthenticateClientResponseError /
// GetBoundProfilePackageResponseError / CancelSessionResponseError enums, keyed
// by the subjectCode of the RSP status the service returned.
var (
	initiateErrorCodes     = map[string]int64{"8.8.1": 1, "8.8.2": 3}                                                             // invalidDpAddress, ciPKIdNotSupported
	authenticateErrorCodes = map[string]int64{"8.1.3": 1, "8.1": 5, "8.1.4": 7, "8.2.5": 8, "8.2.6": 8, "8.8.2": 9, "8.10.1": 10} // eumCertificateInvalid, euiccSignatureInvalid, eidMismatch, noEligibleProfile, ciPKUnknown, invalidTransactionId
	getBPPErrorCodes       = map[string]int64{"8.1": 1, "8.2.7": 3, "8.10.1": 95}                                                 // euiccSignatureInvalid, confirmationCodeRefused, invalidTransactionId
	cancelErrorCodes       = map[string]int64{"8.10.1": 1, "8.1": 2}                                                              // invalidTransactionId, euiccSignatureInvalid
)

// asn1Binding implements the SGP.22 §6.6 ASN.1 binding at the generic path
// /gsma/rsp2/asn1. The request and response bodies are DER-encoded
// RemoteProfileProvisioningRequest/Response envelopes around the function TLV.
func (h *Handler) asn1Binding(w http.ResponseWriter, r *http.Request) {
	fn, inner, ok := asn1bind.DecodeRequest(w, r)
	if !ok {
		return
	}
	// One path carries every function, so name the function explicitly for the
	// audit row (the middleware falls back to the path otherwise).
	common.SetFunction(r.Context(), fn.String())

	switch fn {
	case rsp.FuncInitiateAuthentication:
		h.asn1Initiate(w, inner)
	case rsp.FuncAuthenticateClient:
		h.asn1Authenticate(w, r.Context(), inner)
	case rsp.FuncGetBoundProfilePackage:
		h.asn1GetBPP(w, inner)
	case rsp.FuncCancelSession:
		h.asn1Cancel(w, inner)
	case rsp.FuncHandleNotification:
		if h.Notifs != nil {
			if pending, err := rsp.PendingNotificationFromHandleNotification(inner); err == nil {
				_ = h.Notifs.HandlePendingNotification(r.Context(), pending)
			}
		}
		common.WriteNoContent(w)
	default:
		http.Error(w, "unsupported function", http.StatusBadRequest)
	}
}

func (h *Handler) asn1Initiate(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeInitiateAuthenticationRequest(inner)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseError(1))
		return
	}
	res, err := h.CMAE.Initiate(req.EuiccChallenge, req.EuiccInfo1, req.SmdpAddress)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseError(asn1bind.CodeFor(err, initiateErrorCodes, 2)))
		return
	}
	txn, err := hex.DecodeString(res.TransactionID)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseError(1))
		return
	}
	asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseOk(
		txn, res.ServerSigned1, res.ServerSignature1, res.EuiccCiPKIDToBeUsed, res.ServerCertificate))
}

func (h *Handler) asn1Authenticate(w http.ResponseWriter, ctx context.Context, inner []byte) {
	req, err := rsp.DecodeAuthenticateClientRequest(inner)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs9Error(10)) // invalidTransactionId
		return
	}
	res, err := h.CMAE.AuthenticateClient(ctx, asn1bind.HexUpper(req.TransactionID), req.AuthenticateResponse)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs9Error(asn1bind.CodeFor(err, authenticateErrorCodes, 127)))
		return
	}
	txn, _ := hex.DecodeString(res.TransactionID)
	if res.ACROnly {
		asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs9OkAcr(txn, res.ProfileMetadata))
		return
	}
	asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs9Ok(
		txn, res.ProfileMetadata, res.SmdpSigned2, res.SmdpSignature2, res.SmdpCertificate))
}

func (h *Handler) asn1GetBPP(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeGetBoundProfilePackageRequest(inner)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.GetBoundProfilePackageResponseError(95))
		return
	}
	res, err := h.CMAE.GetBoundProfilePackage(asn1bind.HexUpper(req.TransactionID), req.PrepareDownloadRaw)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.GetBoundProfilePackageResponseError(asn1bind.CodeFor(err, getBPPErrorCodes, 127)))
		return
	}
	txn, _ := hex.DecodeString(res.TransactionID)
	asn1bind.WriteResponse(w, rsp.GetBoundProfilePackageResponseOk(txn, res.BoundProfilePackage))
}

func (h *Handler) asn1Cancel(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeCancelSessionRequestEs9(inner)
	if err != nil {
		asn1bind.WriteResponse(w, rsp.CancelSessionResponseEs9Error(1))
		return
	}
	if _, _, err := h.CMAE.CancelSession(asn1bind.HexUpper(req.TransactionID), inner); err != nil {
		asn1bind.WriteResponse(w, rsp.CancelSessionResponseEs9Error(asn1bind.CodeFor(err, cancelErrorCodes, 127)))
		return
	}
	asn1bind.WriteResponse(w, rsp.CancelSessionResponseEs9Ok())
}
