package es11

import (
	"encoding/hex"
	"net/http"

	"rsp42/internal/api/asn1bind"
	"rsp42/internal/rsp"
)

// ES11 ASN.1 error codes. The numeric space is SGP.22 §6.6's ES11
// InitiateAuthentication / AuthenticateClient response enums (8.9.x subjects),
// keyed by the subjectCode of the RSP status the DS service returned.
var (
	dsInitiateErrorCodes     = map[string]int64{"8.9.1": 1, "8.9.2": 3}              // invalidDpAddress (SM-DS address), ciPKIdNotSupported
	dsAuthenticateErrorCodes = map[string]int64{"8.9.3": 5, "8.9.5": 6, "8.10.1": 7} // euiccSignatureInvalid, eventIdUnknown, invalidTransactionId
)

// asn1Binding implements the SGP.22 §6.6 ASN.1 binding for the SM-DS at the
// generic path /gsma/rsp2/asn1. ES11 reuses the ES9+ InitiateAuthentication
// types and answers AuthenticateClient with AuthenticateClientResponseEs11.
func (h *Handler) asn1Binding(w http.ResponseWriter, r *http.Request) {
	fn, inner, ok := asn1bind.DecodeRequest(w, r)
	if !ok {
		return
	}

	switch fn {
	case rsp.FuncInitiateAuthentication:
		req, err := rsp.DecodeInitiateAuthenticationRequest(inner)
		if err != nil {
			asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseError(1))
			return
		}
		res, err := h.DS.Initiate(req.EuiccChallenge, req.EuiccInfo1, req.SmdpAddress)
		if err != nil {
			asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseError(asn1bind.CodeFor(err, dsInitiateErrorCodes, 2)))
			return
		}
		txn, _ := hex.DecodeString(res.TransactionID)
		asn1bind.WriteResponse(w, rsp.InitiateAuthenticationResponseOk(
			txn, res.ServerSigned1, res.ServerSignature1, res.EuiccCiPKIDToBeUsed, res.ServerCertificate))
	case rsp.FuncAuthenticateClient:
		req, err := rsp.DecodeAuthenticateClientRequest(inner)
		if err != nil {
			asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs11Error(7))
			return
		}
		res, err := h.DS.AuthenticateClient(asn1bind.HexUpper(req.TransactionID), req.AuthenticateResponse)
		if err != nil {
			asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs11Error(asn1bind.CodeFor(err, dsAuthenticateErrorCodes, 127)))
			return
		}
		txn, _ := hex.DecodeString(res.TransactionID)
		asn1bind.WriteResponse(w, rsp.AuthenticateClientResponseEs11Ok(txn, res.EventEntries))
	default:
		http.Error(w, "unsupported function", http.StatusBadRequest)
	}
}
