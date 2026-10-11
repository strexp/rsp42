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
		content = append(content, tlvBytes([]byte{0x04}, r.HashCc)...)
	}
	content = append(content, r.SmdpCertificateDER...)
	return tlvBytes(asn1.Ctx(33, true), content)
}

// ES9+ responses -----------------------------------------------------------

// AuthenticateClientResponseEs9Ok builds a BF3B AuthenticateClientResponseEs9
// OK branch from the raw profile metadata and prepare-download request.
func AuthenticateClientResponseEs9Ok(transactionID, profileMetaData, prepareDownloadRequest []byte) []byte {
	var fields []byte
	fields = append(fields, tlvBytes(asn1.Ctx(0, false), transactionID)...)
	fields = append(fields, profileMetaData...)
	fields = append(fields, prepareDownloadRequest...)
	return tlvBytes(asn1.Ctx(59, true), tlvBytes(asn1.Ctx(0, true), fields))
}

// AuthenticateClientResponseEs9Error builds the error branch.
func AuthenticateClientResponseEs9Error(code int64) []byte {
	return tlvBytes(asn1.Ctx(59, true), tlvBytes(asn1.Ctx(1, true), tlvBytes(asn1.TagInteger, asn1.IntBytes(code))))
}

// GetBoundProfilePackageResponseOk builds a BF3A GetBoundProfilePackageResponse
// OK branch wrapping a BoundProfilePackage.
func GetBoundProfilePackageResponseOk(transactionID, boundProfilePackage []byte) []byte {
	var fields []byte
	fields = append(fields, tlvBytes(asn1.Ctx(0, false), transactionID)...)
	fields = append(fields, boundProfilePackage...)
	return tlvBytes(asn1.Ctx(58, true), tlvBytes(asn1.Ctx(0, true), fields))
}

// GetBoundProfilePackageResponseError builds the error branch.
func GetBoundProfilePackageResponseError(code int64) []byte {
	return tlvBytes(asn1.Ctx(58, true), tlvBytes(asn1.Ctx(1, true), tlvBytes(asn1.TagInteger, asn1.IntBytes(code))))
}

// CancelSessionResponseEs9Ok builds the BF41 CancelSessionResponseEs9 OK branch.
func CancelSessionResponseEs9Ok() []byte {
	return tlvBytes(asn1.Ctx(65, true), tlvBytes(asn1.Ctx(0, true), nil))
}

// CancelSessionResponseEs9Error builds the error branch.
func CancelSessionResponseEs9Error(code int64) []byte {
	return tlvBytes(asn1.Ctx(65, true), tlvBytes(asn1.Ctx(1, true), asn1.IntBytes(code)))
}

// AuthenticateClientResponseEs11Ok builds a BF40 AuthenticateClientResponseEs11
// OK branch from the event entries. Each entry is {eventID, rspServerAddress}.
func AuthenticateClientResponseEs11Ok(transactionID []byte, eventEntries [][2]string) []byte {
	var entries []byte
	for _, e := range eventEntries {
		var item []byte
		item = append(item, tlvBytes([]byte{0x80}, []byte(e[0]))...)
		item = append(item, tlvBytes([]byte{0x81}, []byte(e[1]))...)
		entries = append(entries, tlvBytes([]byte{0x30}, item)...)
	}
	var fields []byte
	fields = append(fields, tlvBytes([]byte{0x80}, transactionID)...)
	fields = append(fields, tlvBytes(asn1.Ctx(1, true), entries)...)
	return tlvBytes(asn1.Ctx(64, true), tlvBytes(asn1.Ctx(0, true), fields))
}
