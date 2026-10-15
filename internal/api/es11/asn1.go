package es11

import (
	"encoding/hex"
	"net/http"

	"rsp42/internal/api/asn1bind"
	"rsp42/internal/hexutil"
	"rsp42/internal/rsp"
)

// ES11 ASN.1 error codes. The numeric space is SGP.22 §6.6's ES11
// InitiateAuthentication / AuthenticateClient response enums. Each table is
// keyed "subject/reason" (SGP.22 §5.2.6 status codes) so that distinct reason
// codes under one subject map to the right enum member.
var (
	// ES11.InitiateAuthentication reuses the ES9+ InitiateAuthenticationResponse
	// enum (§6.6.2.6), i.e. invalidDpAddress(1), euiccVersionNotSupportedByDp(2),
	// ciPKIdNotSupported(3). The subjects are Table 48a's:
	//   invalidDpAddress(1)=8.9.1/3.8, euiccVersionNotSupportedByDp(2)=8.9.3/3.1,
	//   ciPKIdNotSupported(3)=8.9.2/3.1.
	// 8.9.1/1.2 is the format code the service emits for a malformed
	// euiccChallenge/euiccInfo1; the enum has no format member, so it maps to
	// invalidDpAddress(1) (the same subject). 8.9.4/3.7 has no enum member.
	dsInitiateErrorCodes = map[string]int64{
		"8.9.1/3.8": 1,
		"8.9.3/3.1": 2,
		"8.9.2/3.1": 3,
		"8.9.1/1.2": 1,
	}

	// AuthenticateClientResponseEs11 enum (§6.6.2.7), Table 52:
	//   eumCertificateInvalid(1)=8.1.2/6.1, eumCertificateExpired(2)=8.1.2/6.3,
	//   euiccCertificateInvalid(3)=8.1.3/6.1, euiccCertificateExpired(4)=8.1.3/6.3,
	//   euiccSignatureInvalid(5)=8.1/6.1, eventIdUnknown(6)=8.9.5/3.9,
	//   invalidTransactionId(7)=8.10.1/3.9.
	// Table 52's 8.11.1/3.9 (CI used by the EUM Certificate is not a trusted
	// root) has NO member in the ES11 enum (unlike ES9+'s ciPKUnknown(9)), so it
	// falls back to undefinedError(127).
	dsAuthenticateErrorCodes = map[string]int64{
		"8.1.2/6.1":  1,
		"8.1.2/6.3":  2,
		"8.1.3/6.1":  3,
		"8.1.3/6.3":  4,
		"8.1/6.1":    5,
		"8.9.5/3.9":  6,
		"8.10.1/3.9": 7,
	}
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
		res, err := h.DS.AuthenticateClient(hexutil.Upper(req.TransactionID), req.AuthenticateResponse)
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
