package es11

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
)

// asn1Binding implements the SGP.22 §6.6 ASN.1 binding for the SM-DS at the
// generic path /gsma/rsp2/asn1. ES11 reuses the ES9+ InitiateAuthentication
// types and answers AuthenticateClient with AuthenticateClientResponseEs11.
func (h *Handler) asn1Binding(w http.ResponseWriter, r *http.Request) {
	if common.MediaType(r.Header.Get("Content-Type")) != common.ContentTypeASN1 {
		http.Error(w, "unsupported Content-Type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := common.ReadRaw(w, r, 0)
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
		req, err := rsp.DecodeInitiateAuthenticationRequest(inner)
		if err != nil {
			writeASN1(w, rsp.InitiateAuthenticationResponseError(1))
			return
		}
		res, err := h.DS.Initiate(req.EuiccChallenge, req.EuiccInfo1, req.SmdpAddress)
		if err != nil {
			writeASN1(w, rsp.InitiateAuthenticationResponseError(dsInitiateErrorCode(err)))
			return
		}
		txn, _ := hex.DecodeString(res.TransactionID)
		writeASN1(w, rsp.InitiateAuthenticationResponseOk(
			txn, res.ServerSigned1, res.ServerSignature1, res.EuiccCiPKIDToBeUsed, res.ServerCertificate))
	case rsp.FuncAuthenticateClient:
		req, err := rsp.DecodeAuthenticateClientRequest(inner)
		if err != nil {
			writeASN1(w, rsp.AuthenticateClientResponseEs11Error(7))
			return
		}
		res, err := h.DS.AuthenticateClient(hexUpper(req.TransactionID), req.AuthenticateResponse)
		if err != nil {
			writeASN1(w, rsp.AuthenticateClientResponseEs11Error(dsAuthenticateErrorCode(err)))
			return
		}
		txn, _ := hex.DecodeString(res.TransactionID)
		writeASN1(w, rsp.AuthenticateClientResponseEs11Ok(txn, res.EventEntries))
	default:
		http.Error(w, "unsupported function", http.StatusBadRequest)
	}
}

func writeASN1(w http.ResponseWriter, inner []byte) {
	common.WriteASN1(w, rsp.EncodeRemoteProfileProvisioningResponse(inner))
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

func dsInitiateErrorCode(err error) int64 {
	switch subjectCode(err) {
	case "8.9.1":
		return 1 // invalidDpAddress (SM-DS address)
	case "8.9.2":
		return 3 // ciPKIdNotSupported
	}
	return 2
}

func dsAuthenticateErrorCode(err error) int64 {
	switch subjectCode(err) {
	case "8.9.3":
		return 5 // euiccSignatureInvalid
	case "8.9.5":
		return 6 // eventIdUnknown
	case "8.10.1":
		return 7 // invalidTransactionId
	}
	return 127
}

func subjectCode(err error) string {
	var sc *rsp.StatusCode
	if errors.As(err, &sc) {
		return sc.SubjectCode
	}
	return ""
}
