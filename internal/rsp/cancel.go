package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// CancelSession -------------------------------------------------------------

// EuiccCancelSessionSigned is signed by the eUICC on cancel (SGP.22 §5.7.7).
type EuiccCancelSessionSigned struct {
	TransactionID []byte
	SmdpOID       string
	Reason        int64
}

// CancelSessionResponseOk is the OK branch of CancelSessionResponse.
type CancelSessionResponseOk struct {
	Signed    *EuiccCancelSessionSigned
	SignedRaw []byte
	Signature []byte
}

// DecodeCancelSessionResponse parses a BF41 CancelSessionResponse CHOICE.
func DecodeCancelSessionResponse(raw []byte) (*CancelSessionResponseOk, int64, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, 0, err
	}
	if hex.EncodeToString(t.Tag) != "bf41" {
		return nil, 0, fmt.Errorf("rsp: CancelSessionResponse unexpected tag %X", t.Tag)
	}
	ch, err := splitChoice(t)
	if err != nil {
		return nil, 0, err
	}
	if ch.hasOK {
		kids, err := ch.ok.Children()
		if err != nil {
			return nil, 0, err
		}
		out := &CancelSessionResponseOk{}
		for _, k := range kids {
			switch {
			case isSequence(k) && out.Signed == nil:
				out.SignedRaw = k.Raw
				out.Signed, err = DecodeEuiccCancelSessionSigned(k)
				if err != nil {
					return nil, 0, err
				}
			case isSignature(k):
				out.Signature = k.Value
			}
		}
		return out, 0, nil
	} else if ch.hasErr {
		if n, ok := choiceErrorCode(ch.errAlt); ok {
			return nil, n, nil
		}
	}
	// Some peers encode the error INTEGER directly in [1] under the CHOICE (an
	// implicit primitive tag, 0x81) rather than as a constructed [1]
	// alternative; splitChoice only recognises the constructed form.
	if n, ok := choiceErrorCode(t); ok {
		return nil, n, nil
	}
	return nil, 0, fmt.Errorf("rsp: CancelSessionResponse has no recognised alternative")
}

// DecodeEuiccCancelSessionSigned parses a EuiccCancelSessionSigned SEQUENCE.
func DecodeEuiccCancelSessionSigned(t asn1.TLV) (*EuiccCancelSessionSigned, error) {
	s := &EuiccCancelSessionSigned{
		TransactionID: childBytes(t, asn1.Ctx(0, false)),
	}
	if v, ok := t.Find(asn1.Ctx(1, false)); ok {
		s.SmdpOID, _ = asn1.DecodeOID(v.Value)
	}
	if v, ok := t.Find(asn1.Ctx(2, false)); ok {
		s.Reason, _ = v.Int()
	}
	return s, nil
}

// CancelSessionRequestEs9 is sent from the LPA to ES9+.CancelSession.
type CancelSessionRequestEs9 struct {
	TransactionID []byte
	// The LPA embeds the ES10b CancelSessionResponse; we only need the reason.
	Reason int64
}

// DecodeCancelSessionRequestEs9 parses a BF41 CancelSessionRequestEs9.
func DecodeCancelSessionRequestEs9(raw []byte) (*CancelSessionRequestEs9, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf41" {
		return nil, fmt.Errorf("rsp: CancelSessionRequestEs9 unexpected tag %X", t.Tag)
	}
	out := &CancelSessionRequestEs9{TransactionID: childBytes(t, asn1.Ctx(0, false))}
	if cs, ok := t.Find(asn1.Ctx(1, true)); ok {
		if resp, ok := cs.Find([]byte{0xbf, 0x41}); ok {
			if reason, found := CancelSessionResponseFromTLV(resp); found {
				out.Reason = reason
			}
		}
	}
	return out, nil
}

// CancelSessionResponseFromTLV extracts the reason carried by an ES10b
// CancelSessionResponse: the reason field of the ok alternative, or the error
// code of the error alternative. found is false when the response carries
// neither, so callers do not have to treat a magic value as "missing" (the
// previous signature returned -1 for that case).
func CancelSessionResponseFromTLV(t asn1.TLV) (reason int64, found bool) {
	ch, err := splitChoice(t)
	if err != nil {
		return 0, false
	}
	if ch.hasOK {
		if kids, err := ch.ok.Children(); err == nil {
			for _, k := range kids {
				if isSequence(k) {
					if s, err := DecodeEuiccCancelSessionSigned(k); err == nil {
						return s.Reason, true
					}
				}
			}
		}
	}
	// Some peers place the code directly in [1] one level up instead of nesting
	// it in the error alternative.
	if v, ok := t.Find(asn1.Ctx(1, false)); ok {
		if n, err := v.Int(); err == nil {
			return n, true
		}
	}
	if ch.hasErr {
		if v, ok := ch.errAlt.Find(asn1.Ctx(1, false)); ok {
			if n, err := v.Int(); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}
