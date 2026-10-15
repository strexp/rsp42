package rsp

import "rsp42/internal/asn1"

// PrepareDownloadRequest ----------------------------------------------------

// PrepareDownloadRequest is returned inside ES9+.AuthenticateClient (SGP.22 §5.7.4).
type PrepareDownloadRequest struct {
	SmdpSigned2Raw     []byte // raw SmdpSigned2 SEQUENCE
	SmdpSignature2Raw  []byte // raw 5F37 signature TLV
	HashCc             []byte // optional
	SmdpCertificateDER []byte // CERT.DPpb DER
}

// Encode returns the BF21 encoding of the request.
func (r *PrepareDownloadRequest) Encode() []byte {
	content := append([]byte{}, r.SmdpSigned2Raw...)
	content = append(content, r.SmdpSignature2Raw...)
	if len(r.HashCc) > 0 {
		content = append(content, asn1.RawTagged([]byte{0x04}, r.HashCc)...)
	}
	content = append(content, r.SmdpCertificateDER...)
	return asn1.RawTagged(asn1.Ctx(33, true), content)
}

// ES9+ responses -----------------------------------------------------------

// AuthenticateClientResponseEs9Ok builds the BF3B
// AuthenticateClientResponseEs9 OK branch (SGP.22 §6.6.2.2):
//
//	BF3B { A0 { transactionId, profileMetaData, smdpSigned2, smdpSignature2,
//	            smdpCertificate } }
func AuthenticateClientResponseEs9Ok(transactionID, profileMetaData, smdpSigned2, smdpSignature2, smdpCertificate []byte) []byte {
	var fields []byte
	fields = append(fields, asn1.RawTagged(asn1.Ctx(0, false), transactionID)...)
	fields = append(fields, profileMetaData...)
	fields = append(fields, smdpSigned2...)
	fields = append(fields, smdpSignature2...)
	fields = append(fields, smdpCertificate...)
	return asn1.RawTagged(asn1.Ctx(tagAuthenticateClient, true), asn1.RawTagged(asn1.Ctx(0, true), fields))
}

// AuthenticateClientResponseEs9OkAcr builds the ACR OK branch
// (`authenticateClientOkAcr [5]`), which carries only the transaction id and the
// profile metadata (SGP.22 §3.1.7.2).
func AuthenticateClientResponseEs9OkAcr(transactionID, profileMetaData []byte) []byte {
	var fields []byte
	fields = append(fields, asn1.RawTagged(asn1.Ctx(0, false), transactionID)...)
	fields = append(fields, profileMetaData...)
	return asn1.RawTagged(asn1.Ctx(tagAuthenticateClient, true), asn1.RawTagged(asn1.Ctx(5, true), fields))
}

// AuthenticateClientResponseEs9Error builds the error branch
// (`authenticateClientError [1] INTEGER`).
func AuthenticateClientResponseEs9Error(code int64) []byte {
	return asn1.RawTagged(asn1.Ctx(tagAuthenticateClient, true), asn1.RawTagged(asn1.Ctx(1, false), asn1.IntBytes(code)))
}

// GetBoundProfilePackageResponseOk builds a BF3A GetBoundProfilePackageResponse
// OK branch wrapping a BoundProfilePackage.
func GetBoundProfilePackageResponseOk(transactionID, boundProfilePackage []byte) []byte {
	var fields []byte
	fields = append(fields, asn1.RawTagged(asn1.Ctx(0, false), transactionID)...)
	fields = append(fields, boundProfilePackage...)
	return asn1.RawTagged(asn1.Ctx(tagGetBoundProfile, true), asn1.RawTagged(asn1.Ctx(0, true), fields))
}

// GetBoundProfilePackageResponseError builds the error branch
// (`getBoundProfilePackageError INTEGER`).
func GetBoundProfilePackageResponseError(code int64) []byte {
	return asn1.RawTagged(asn1.Ctx(tagGetBoundProfile, true), asn1.RawTagged(asn1.Ctx(1, false), asn1.IntBytes(code)))
}

// CancelSessionResponseEs9Ok builds the BF41 CancelSessionResponseEs9 OK branch.
func CancelSessionResponseEs9Ok() []byte {
	return asn1.RawTagged(asn1.Ctx(tagCancelSessionEs9, true), asn1.RawTagged(asn1.Ctx(0, true), nil))
}

// CancelSessionResponseEs9Error builds the error branch
// (`cancelSessionError INTEGER`).
func CancelSessionResponseEs9Error(code int64) []byte {
	return asn1.RawTagged(asn1.Ctx(tagCancelSessionEs9, true), asn1.RawTagged(asn1.Ctx(1, false), asn1.IntBytes(code)))
}

// AuthenticateClientResponseEs11Ok builds a BF40 AuthenticateClientResponseEs11
// OK branch from the event entries. Each entry is {eventID, rspServerAddress}.
func AuthenticateClientResponseEs11Ok(transactionID []byte, eventEntries [][2]string) []byte {
	var entries []byte
	for _, e := range eventEntries {
		var item []byte
		item = append(item, asn1.RawTagged([]byte{0x80}, []byte(e[0]))...)
		item = append(item, asn1.RawTagged([]byte{0x81}, []byte(e[1]))...)
		entries = append(entries, asn1.RawTagged([]byte{0x30}, item)...)
	}
	var fields []byte
	fields = append(fields, asn1.RawTagged([]byte{0x80}, transactionID)...)
	fields = append(fields, asn1.RawTagged(asn1.Ctx(1, true), entries)...)
	return asn1.RawTagged(asn1.Ctx(tagAuthenticateEs11, true), asn1.RawTagged(asn1.Ctx(0, true), fields))
}

// AuthenticateClientResponseEs11Error builds the BF40 error branch
// (`authenticateClientError INTEGER`).
func AuthenticateClientResponseEs11Error(code int64) []byte {
	return asn1.RawTagged(asn1.Ctx(tagAuthenticateEs11, true), asn1.RawTagged(asn1.Ctx(1, false), asn1.IntBytes(code)))
}
