package es9plus

import (
	"context"
	"encoding/hex"
	"net/http"

	"rsp42/internal/api/asn1bind"
	"rsp42/internal/api/common"
	"rsp42/internal/hexutil"
	"rsp42/internal/rsp"
)

// ES9+ ASN.1 error codes. The numeric space is SGP.22 §6.6's
// InitiateAuthenticationResponseError / AuthenticateClientResponseError /
// GetBoundProfilePackageResponseError / CancelSessionResponseError enums. Each
// table is keyed "subject/reason" (SGP.22 §5.2.6 status codes; the governing
// function tables are cited per entry) so that distinct reason codes under one
// subject map to the right enum member.
var (
	// InitiateAuthenticationResponse enum (§6.6.2.1), Table 37:
	//   invalidDpAddress(1)=8.8.1/3.8, euiccVersionNotSupportedByDp(2)=8.8.3/3.1,
	//   ciPKIdNotSupported(3)=8.8.2/3.1.
	// 8.8.1/1.2 is the format code the service emits for a malformed
	// euiccChallenge/euiccInfo1; the enum has no format member, so it maps to
	// invalidDpAddress(1) (the same subject). 8.8.4/3.7 has no enum member.
	initiateErrorCodes = map[string]int64{
		"8.8.1/3.8": 1,
		"8.8.3/3.1": 2,
		"8.8.2/3.1": 3,
		"8.8.1/1.2": 1,
	}

	// AuthenticateClientResponseEs9 enum (§6.6.2.2), Table 43:
	//   eumCertificateInvalid(1)=8.1.2/6.1, eumCertificateExpired(2)=8.1.2/6.3,
	//   euiccCertificateInvalid(3)=8.1.3/6.1, euiccCertificateExpired(4)=8.1.3/6.3,
	//   euiccSignatureInvalid(5)=8.1/6.1, matchingIdRefused(6)=8.2.6/3.8,
	//   eidMismatch(7)=8.1.1/3.8, noEligibleProfile(8)=8.2.5/4.3,
	//   ciPKUnknown(9)=8.11.1/3.9, invalidTransactionId(10)=8.10.1/3.9,
	//   insufficientMemory(11)=8.1/4.8, downloadOrderExpired(18)=8.8.5/4.10.
	// Table 43's 8.2/1.2 (Profile not yet released) and 8.8.5/6.4 (download
	// retries exceeded) have no enum member: they fall back to undefinedError(127).
	authenticateErrorCodes = map[string]int64{
		"8.1.2/6.1":  1,
		"8.1.2/6.3":  2,
		"8.1.3/6.1":  3,
		"8.1.3/6.3":  4,
		"8.1/6.1":    5,
		"8.2.6/3.8":  6,
		"8.1.1/3.8":  7,
		"8.2.5/4.3":  8,
		"8.11.1/3.9": 9,
		"8.10.1/3.9": 10,
		"8.1/4.8":    11,
		"8.8.5/4.10": 18,
	}

	// GetBoundProfilePackageResponse enum (§6.6.2.3), Table 40:
	//   euiccSignatureInvalid(1)=8.1/6.1, confirmationCodeMissing(2)=8.2.7/2.2,
	//   confirmationCodeRefused(3)=8.2.7/3.8,
	//   confirmationCodeRetriesExceeded(4)=8.2.7/6.4, bppRebindingRefused(5)=8.2/3.7,
	//   invalidTransactionId(95)=8.10.1/3.9.
	getBPPErrorCodes = map[string]int64{
		"8.1/6.1":    1,
		"8.2.7/2.2":  2,
		"8.2.7/3.8":  3,
		"8.2.7/6.4":  4,
		"8.2/3.7":    5,
		"8.10.1/3.9": 95,
	}

	// CancelSessionResponseEs9 enum (§6.6.2.5), Table 46:
	//   invalidTransactionId(1)=8.10.1/3.9, euiccSignatureInvalid(2)=8.1/6.1.
	// 8.8/3.10 (SM-DP+ OID invalid) is not produced: the §5.6.5 signature/OID
	// verification is the registered R4 gap.
	cancelErrorCodes = map[string]int64{
		"8.10.1/3.9": 1,
		"8.1/6.1":    2,
	}
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
	res, err := h.CMAE.AuthenticateClient(ctx, hexutil.Upper(req.TransactionID), req.AuthenticateResponse)
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
	res, err := h.CMAE.GetBoundProfilePackage(hexutil.Upper(req.TransactionID), req.PrepareDownloadRaw)
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
	if _, _, err := h.CMAE.CancelSession(hexutil.Upper(req.TransactionID), inner); err != nil {
		asn1bind.WriteResponse(w, rsp.CancelSessionResponseEs9Error(asn1bind.CodeFor(err, cancelErrorCodes, 127)))
		return
	}
	asn1bind.WriteResponse(w, rsp.CancelSessionResponseEs9Ok())
}
