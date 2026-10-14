package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

type PrepareDownloadResponseOk struct {
	EuiccSigned2    *EUICCSigned2
	EuiccSigned2Raw []byte
	EuiccSignature2 []byte
}

// PrepareDownloadResponseError is the error branch.
type PrepareDownloadResponseError struct {
	TransactionID     []byte
	DownloadErrorCode int64
}

// DecodePrepareDownloadResponse parses a PrepareDownloadResponse (BF21) CHOICE.
func DecodePrepareDownloadResponse(raw []byte) (*PrepareDownloadResponseOk, *PrepareDownloadResponseError, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf21" {
		return nil, nil, fmt.Errorf("rsp: PrepareDownloadResponse unexpected tag %X", t.Tag)
	}
	ch, err := splitChoice(t)
	if err != nil {
		return nil, nil, err
	}
	if ch.hasOK {
		kids, err := ch.ok.Children()
		if err != nil {
			return nil, nil, err
		}
		out := &PrepareDownloadResponseOk{}
		for _, k := range kids {
			switch {
			case isSequence(k) && out.EuiccSigned2 == nil:
				out.EuiccSigned2Raw = k.Raw
				out.EuiccSigned2, err = DecodeEUICCSigned2(k)
				if err != nil {
					return nil, nil, err
				}
			case isSignature(k):
				out.EuiccSignature2 = k.Value
			}
		}
		return out, nil, nil
	} else if ch.hasErr {
		errResp := &PrepareDownloadResponseError{TransactionID: childBytes(ch.errAlt, asn1.Ctx(0, false))}
		errResp.DownloadErrorCode, _ = choiceErrorCode(ch.errAlt)
		return nil, errResp, nil
	}
	return nil, nil, fmt.Errorf("rsp: PrepareDownloadResponse has no recognised alternative")
}

// AuthenticateServer responses ---------------------------------------------

// AuthenticateResponseOk is the OK branch of AuthenticateServerResponse.
type AuthenticateResponseOk struct {
	EuiccSigned1     *EuiccSigned1
	EuiccSignature1  []byte
	EuiccCertificate []byte
	EumCertificate   []byte
	// OtherCertsInChain carries any additional certificates between the EUM and
	// the CI (SGP.22 §5.7.9 / §6.5.2, eUICC certificate chain variants).
	OtherCertsInChain [][]byte
}

// AuthenticateResponseError is the error branch.
type AuthenticateResponseError struct {
	TransactionID         []byte
	AuthenticateErrorCode int64
}

// DecodeAuthenticateServerResponse parses an AuthenticateServerResponse (BF38).
func DecodeAuthenticateServerResponse(raw []byte) (*AuthenticateResponseOk, *AuthenticateResponseError, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf38" {
		return nil, nil, fmt.Errorf("rsp: AuthenticateServerResponse unexpected tag %X", t.Tag)
	}
	ch, err := splitChoice(t)
	if err != nil {
		return nil, nil, err
	}
	if ch.hasOK {
		kids, err := ch.ok.Children()
		if err != nil {
			return nil, nil, err
		}
		out := &AuthenticateResponseOk{}
		var certs [][]byte
		for _, k := range kids {
			switch {
			case isSequence(k) && out.EuiccSigned1 == nil:
				out.EuiccSigned1, err = DecodeEuiccSigned1(k)
				if err != nil {
					return nil, nil, err
				}
			case isSignature(k):
				out.EuiccSignature1 = k.Value
			case isSequence(k):
				certs = append(certs, k.Raw)
			}
		}
		if len(certs) >= 1 {
			out.EuiccCertificate = certs[0]
		}
		if len(certs) >= 2 {
			out.EumCertificate = certs[1]
		}
		if len(certs) > 2 {
			out.OtherCertsInChain = certs[2:]
		}
		return out, nil, nil
	} else if ch.hasErr {
		errResp := &AuthenticateResponseError{TransactionID: childBytes(ch.errAlt, asn1.Ctx(0, false))}
		errResp.AuthenticateErrorCode, _ = choiceErrorCode(ch.errAlt)
		return nil, errResp, nil
	}
	return nil, nil, fmt.Errorf("rsp: AuthenticateServerResponse has no recognised alternative")
}

// certificateSequenceValues returns the raw bytes of every universal SEQUENCE
// child of t (used to extract certificates).
func certificateSequenceValues(t asn1.TLV) [][]byte {
	kids, err := t.Children()
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, k := range kids {
		if len(k.Tag) == 1 && k.Tag[0] == 0x30 {
			out = append(out, k.Raw)
		}
	}
	return out
}
