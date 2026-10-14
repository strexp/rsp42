package rsp

import (
	"fmt"

	"rsp42/internal/asn1"
)

// ExtractEuiccSigned1 returns the exact wire bytes of the euiccSigned1 data
// object contained in an AuthenticateServerResponse (SGP.22 §5.7.13).
func ExtractEuiccSigned1(authenticateServerResponse []byte) ([]byte, error) {
	ok, errResp, err := DecodeAuthenticateServerResponse(authenticateServerResponse)
	if err != nil {
		return nil, err
	}
	if ok == nil {
		if errResp != nil {
			return nil, fmt.Errorf("rsp: authenticateResponseError %d", errResp.AuthenticateErrorCode)
		}
		return nil, fmt.Errorf("rsp: no euiccSigned1")
	}
	// Re-encode is not used: locate the raw slice directly.
	t, _, err := asn1.ReadTLV(authenticateServerResponse)
	if err != nil {
		return nil, err
	}
	a0, hasOK, _, _ := splitChoice(t)
	if !hasOK {
		return nil, fmt.Errorf("rsp: no authenticateResponseOk")
	}
	kids, err := a0.Children()
	if err != nil {
		return nil, err
	}
	for _, k := range kids {
		if isSequence(k) {
			return k.Raw, nil
		}
	}
	return nil, fmt.Errorf("rsp: euiccSigned1 not found")
}

// ExtractEuiccSigned2 returns the exact wire bytes of the euiccSigned2 data
// object contained in a PrepareDownloadResponse (SGP.22 §5.7.4).
func ExtractEuiccSigned2(prepareDownloadResponse []byte) ([]byte, error) {
	ok, errResp, err := DecodePrepareDownloadResponse(prepareDownloadResponse)
	if err != nil {
		return nil, err
	}
	if ok == nil {
		if errResp != nil {
			return nil, fmt.Errorf("rsp: downloadResponseError %d", errResp.DownloadErrorCode)
		}
		return nil, fmt.Errorf("rsp: no euiccSigned2")
	}
	if len(ok.EuiccSigned2Raw) == 0 {
		return nil, fmt.Errorf("rsp: euiccSigned2 not found")
	}
	return ok.EuiccSigned2Raw, nil
}

// SignatureValue returns the raw signature bytes from a 5F37 signature element.
// It accepts either a DER TLV (5F37 40 <sig>) or the raw signature itself.
func SignatureValue(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	if t, _, err := asn1.ReadTLV(b); err == nil && len(t.Tag) == 2 && t.Tag[0] == 0x5f && t.Tag[1] == 0x37 {
		return t.Value
	}
	return b
}

// WrapSignature builds the 5F37 signature TLV from raw signature bytes.
func WrapSignature(sig []byte) []byte {
	return tlvBytes(asn1.App(55, false), sig)
}
