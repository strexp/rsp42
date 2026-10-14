package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// SGP.22 §6.6 ASN.1 binding.
//
// The HTTP body is a DER-encoded RemoteProfileProvisioningRequest/Response: an
// explicit [2] wrapper (tag A2) around the chosen function's TLV. The
// RSPDefinitions module uses AUTOMATIC TAGS, so untagged components receive
// context tags automatically and context tags on CHOICE-typed components are
// explicit (producing a nested wrapper, e.g. authenticateServerResponse [56] ->
// BF38 { BF38 { ... } }).
const (
	tagEnvelope           = 2  // [2] CHOICE -> A2
	tagInitiateAuth       = 57 // BF39
	tagAuthenticateClient = 59 // BF3B
	tagGetBoundProfile    = 58 // BF3A
	tagCancelSessionEs9   = 65 // BF41
	tagHandleNotification = 61 // BF3D
	tagAuthenticateEs11   = 64 // BF40
)

// ASN1Function identifies the SGP.22 function carried by an ASN.1 binding
// message.
type ASN1Function int

// ASN.1 binding functions.
const (
	FuncInitiateAuthentication ASN1Function = iota
	FuncAuthenticateClient
	FuncGetBoundProfilePackage
	FuncCancelSession
	FuncHandleNotification
	FuncAuthenticateClientEs11
)

func functionForTag(tag string) (ASN1Function, bool) {
	switch tag {
	case "bf39":
		return FuncInitiateAuthentication, true
	case "bf3b":
		return FuncAuthenticateClient, true
	case "bf3a":
		return FuncGetBoundProfilePackage, true
	case "bf41":
		return FuncCancelSession, true
	case "bf3d":
		return FuncHandleNotification, true
	case "bf40":
		return FuncAuthenticateClientEs11, true
	}
	return 0, false
}

// DecodeRemoteProfileProvisioningRequest unwraps the A2 envelope and returns
// the identified function together with the raw inner TLV.
func DecodeRemoteProfileProvisioningRequest(raw []byte) (ASN1Function, []byte, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return 0, nil, err
	}
	if hex.EncodeToString(t.Tag) != "a2" {
		return 0, nil, fmt.Errorf("rsp: RemoteProfileProvisioningRequest unexpected tag %X", t.Tag)
	}
	inner, ok := t.First()
	if !ok {
		return 0, nil, fmt.Errorf("rsp: RemoteProfileProvisioningRequest is empty")
	}
	fn, ok := functionForTag(hex.EncodeToString(inner.Tag))
	if !ok {
		return 0, nil, fmt.Errorf("rsp: unknown ASN.1 binding function tag %X", inner.Tag)
	}
	return fn, inner.Raw, nil
}

// EncodeRemoteProfileProvisioningResponse wraps a function response TLV in the
// A2 envelope.
func EncodeRemoteProfileProvisioningResponse(inner []byte) []byte {
	return tlvBytes(asn1.Ctx(tagEnvelope, true), inner)
}

// InitiateAuthentication ----------------------------------------------------

// InitiateAuthenticationRequest is the ES9+/ES11 initiateAuthentication request
// (SGP.22 §6.6.2.1).
type InitiateAuthenticationRequest struct {
	EuiccChallenge []byte
	SmdpAddress    string
	EuiccInfo1     []byte
}

// DecodeInitiateAuthenticationRequest parses a BF39 InitiateAuthenticationRequest.
func DecodeInitiateAuthenticationRequest(raw []byte) (*InitiateAuthenticationRequest, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf39" {
		return nil, fmt.Errorf("rsp: InitiateAuthenticationRequest unexpected tag %X", t.Tag)
	}
	req := &InitiateAuthenticationRequest{
		EuiccChallenge: childBytes(t, asn1.Ctx(1, false)),
		SmdpAddress:    childString(t, asn1.Ctx(3, false)),
	}
	if info, ok := t.Find([]byte{0xbf, 0x20}); ok {
		req.EuiccInfo1 = info.Raw
	}
	if len(req.EuiccChallenge) != 16 || len(req.EuiccInfo1) == 0 {
		return nil, fmt.Errorf("rsp: InitiateAuthenticationRequest missing euiccChallenge/euiccInfo1")
	}
	return req, nil
}

// InitiateAuthenticationResponseOk builds the BF39 OK branch:
//
//	BF39 { A0 { transactionId, serverSigned1, serverSignature1,
//	            euiccCiPKIdToBeUsed, serverCertificate } }
func InitiateAuthenticationResponseOk(transactionID, serverSigned1, serverSignature1, euiccCiPKIDToBeUsed, serverCertificate []byte) []byte {
	var ok []byte
	ok = append(ok, tlvBytes(asn1.Ctx(0, false), transactionID)...)
	ok = append(ok, serverSigned1...)
	ok = append(ok, serverSignature1...)
	ok = append(ok, euiccCiPKIDToBeUsed...)
	ok = append(ok, serverCertificate...)
	return tlvBytes(asn1.Ctx(tagInitiateAuth, true), tlvBytes(asn1.Ctx(0, true), ok))
}

// InitiateAuthenticationResponseError builds the BF39 error branch.
func InitiateAuthenticationResponseError(code int64) []byte {
	return tlvBytes(asn1.Ctx(tagInitiateAuth, true), tlvBytes(asn1.Ctx(1, false), asn1.IntBytes(code)))
}

// PendingNotificationFromHandleNotification extracts the PendingNotification
// (A0-wrapped) from a BF3D HandleNotification, ready for
// NotificationService.HandlePendingNotification.
func PendingNotificationFromHandleNotification(raw []byte) ([]byte, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf3d" {
		return nil, fmt.Errorf("rsp: HandleNotification unexpected tag %X", t.Tag)
	}
	if p, ok := t.First(); ok {
		return p.Raw, nil
	}
	return nil, fmt.Errorf("rsp: HandleNotification is empty")
}
