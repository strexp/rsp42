// Package asn1bind holds the HTTP plumbing shared by the SGP.22 §6.6 ASN.1
// binding of ES9+ and ES11: the DER RemoteProfileProvisioningRequest/Response
// envelope, the media-type gate, the transaction-id hex conversion and the
// interface-specific numeric status-code lookup.
//
// The function dispatch stays with each interface: ES9+ and ES11 answer
// different function sets, and their numeric error spaces (8.x vs 8.9.x) are
// not interchangeable.
package asn1bind

import (
	"errors"
	"net/http"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
)

// DecodeRequest accepts an ASN.1 binding request and returns its function tag
// and inner TLV. On failure it writes the HTTP response and reports ok=false.
func DecodeRequest(w http.ResponseWriter, r *http.Request) (rsp.ASN1Function, []byte, bool) {
	if common.MediaType(r.Header.Get("Content-Type")) != common.ContentTypeASN1 {
		http.Error(w, "unsupported Content-Type", http.StatusUnsupportedMediaType)
		return 0, nil, false
	}
	body, err := common.ReadRaw(w, r, 0)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return 0, nil, false
	}
	fn, inner, err := rsp.DecodeRemoteProfileProvisioningRequest(body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return 0, nil, false
	}
	return fn, inner, true
}

// WriteResponse wraps an inner function TLV in the RemoteProfileProvisioning
// Response envelope.
func WriteResponse(w http.ResponseWriter, inner []byte) {
	common.WriteASN1(w, rsp.EncodeRemoteProfileProvisioningResponse(inner))
}

// SubjectCode returns the subjectCode of a *rsp.StatusCode error, or "" when
// the error carries no RSP classification.
func SubjectCode(err error) string {
	var sc *rsp.StatusCode
	if errors.As(err, &sc) {
		return sc.SubjectCode
	}
	return ""
}

// StatusPair returns the subjectCode and reasonCode of a *rsp.StatusCode error,
// or two empty strings when the error carries no RSP classification.
func StatusPair(err error) (subject, reason string) {
	var sc *rsp.StatusCode
	if errors.As(err, &sc) {
		return sc.SubjectCode, sc.ReasonCode
	}
	return "", ""
}

// CodeFor maps err to the interface-specific ASN.1 error code registered in
// table, or returns fallback when it is not mapped.
//
// A table may key entries by "subject/reason" (preferred: one subject can carry
// several spec rows whose reason codes belong to different enums) or by the
// subject alone. The pair key wins; a subject-only entry is the fallback so a
// caller that passes a legacy table without slashes keeps working.
func CodeFor(err error, table map[string]int64, fallback int64) int64 {
	subject, reason := StatusPair(err)
	if subject == "" {
		return fallback
	}
	if reason != "" {
		if code, ok := table[subject+"/"+reason]; ok {
			return code
		}
	}
	if code, ok := table[subject]; ok {
		return code
	}
	return fallback
}
