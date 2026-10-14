package es9plus

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
)

// asn1Binding implements the SGP.22 §6.6 ASN.1 binding at the generic path
// /gsma/rsp2/asn1. The request and response bodies are DER-encoded
// RemoteProfileProvisioningRequest/Response envelopes around the function TLV.
func (h *Handler) asn1Binding(w http.ResponseWriter, r *http.Request) {
	if common.MediaType(r.Header.Get("Content-Type")) != common.ContentTypeASN1 {
		http.Error(w, "unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	fn, inner, err := rsp.DecodeRemoteProfileProvisioningRequest(body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	switch fn {
	case rsp.FuncInitiateAuthentication:
		h.asn1Initiate(w, inner)
	case rsp.FuncAuthenticateClient:
		h.asn1Authenticate(w, inner)
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

func writeASN1Response(w http.ResponseWriter, inner []byte) {
	common.WriteASN1(w, rsp.EncodeRemoteProfileProvisioningResponse(inner))
}

func (h *Handler) asn1Initiate(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeInitiateAuthenticationRequest(inner)
	if err != nil {
		writeASN1Response(w, rsp.InitiateAuthenticationResponseError(1))
		return
	}
	res, err := h.CMAE.Initiate(req.EuiccChallenge, req.EuiccInfo1, req.SmdpAddress)
	if err != nil {
		writeASN1Response(w, rsp.InitiateAuthenticationResponseError(initiateErrorCode(err)))
		return
	}
	txn, err := hex.DecodeString(res.TransactionID)
	if err != nil {
		writeASN1Response(w, rsp.InitiateAuthenticationResponseError(1))
		return
	}
	writeASN1Response(w, rsp.InitiateAuthenticationResponseOk(
		txn, res.ServerSigned1, res.ServerSignature1, res.EuiccCiPKIDToBeUsed, res.ServerCertificate))
}

func (h *Handler) asn1Authenticate(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeAuthenticateClientRequest(inner)
	if err != nil {
		writeASN1Response(w, rsp.AuthenticateClientResponseEs9Error(10)) // invalidTransactionId
		return
	}
	res, err := h.CMAE.AuthenticateClient(hexUpper(req.TransactionID), req.AuthenticateResponse)
	if err != nil {
		writeASN1Response(w, rsp.AuthenticateClientResponseEs9Error(authenticateErrorCode(err)))
		return
	}
	txn, _ := hex.DecodeString(res.TransactionID)
	if res.ACROnly {
		writeASN1Response(w, rsp.AuthenticateClientResponseEs9OkAcr(txn, res.ProfileMetadata))
		return
	}
	writeASN1Response(w, rsp.AuthenticateClientResponseEs9Ok(
		txn, res.ProfileMetadata, res.SmdpSigned2, res.SmdpSignature2, res.SmdpCertificate))
}

func (h *Handler) asn1GetBPP(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeGetBoundProfilePackageRequest(inner)
	if err != nil {
		writeASN1Response(w, rsp.GetBoundProfilePackageResponseError(95))
		return
	}
	res, err := h.CMAE.GetBoundProfilePackage(hexUpper(req.TransactionID), req.PrepareDownloadRaw)
	if err != nil {
		writeASN1Response(w, rsp.GetBoundProfilePackageResponseError(getBPPErrorCode(err)))
		return
	}
	txn, _ := hex.DecodeString(res.TransactionID)
	writeASN1Response(w, rsp.GetBoundProfilePackageResponseOk(txn, res.BoundProfilePackage))
}

func (h *Handler) asn1Cancel(w http.ResponseWriter, inner []byte) {
	req, err := rsp.DecodeCancelSessionRequestEs9(inner)
	if err != nil {
		writeASN1Response(w, rsp.CancelSessionResponseEs9Error(1))
		return
	}
	if _, _, err := h.CMAE.CancelSession(hexUpper(req.TransactionID), inner); err != nil {
		writeASN1Response(w, rsp.CancelSessionResponseEs9Error(cancelErrorCode(err)))
		return
	}
	writeASN1Response(w, rsp.CancelSessionResponseEs9Ok())
}

// hexUpper encodes transaction id bytes as the uppercase hex string expected by
// the service layer (and the JSON binding).
func hexUpper(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

func subjectCode(err error) string {
	var sc *rsp.StatusCode
	if errors.As(err, &sc) {
		return sc.SubjectCode
	}
	return ""
}

func initiateErrorCode(err error) int64 {
	switch subjectCode(err) {
	case "8.8.1":
		return 1 // invalidDpAddress
	case "8.8.2":
		return 3 // ciPKIdNotSupported
	}
	return 2 // euiccVersionNotSupportedByDp
}

func authenticateErrorCode(err error) int64 {
	switch subjectCode(err) {
	case "8.1.3":
		return 1 // eumCertificateInvalid
	case "8.1":
		return 5 // euiccSignatureInvalid
	case "8.1.4":
		return 7 // eidMismatch
	case "8.2.5", "8.2.6":
		return 8 // noEligibleProfile
	case "8.8.2":
		return 9 // ciPKUnknown
	case "8.10.1":
		return 10 // invalidTransactionId
	}
	return 127 // undefinedError
}

func getBPPErrorCode(err error) int64 {
	switch subjectCode(err) {
	case "8.1":
		return 1 // euiccSignatureInvalid
	case "8.2.7":
		return 3 // confirmationCodeRefused
	case "8.10.1":
		return 95 // invalidTransactionId
	}
	return 127
}

func cancelErrorCode(err error) int64 {
	switch subjectCode(err) {
	case "8.10.1":
		return 1 // invalidTransactionId
	case "8.1":
		return 2 // euiccSignatureInvalid
	}
	return 127
}
