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
	if ok, found := t.Find(asn1.Ctx(0, true)); found {
		kids, err := ok.Children()
		if err != nil {
			return nil, 0, err
		}
		out := &CancelSessionResponseOk{}
		for _, k := range kids {
			switch {
			case len(k.Tag) == 1 && k.Tag[0] == 0x30 && out.Signed == nil:
				out.SignedRaw = k.Raw
				out.Signed, err = DecodeEuiccCancelSessionSigned(k)
				if err != nil {
					return nil, 0, err
				}
			case len(k.Tag) == 2 && k.Tag[0] == 0x5f && k.Tag[1] == 0x37:
				out.Signature = k.Value
			}
		}
		return out, 0, nil
	}
	if e, found := t.Find(asn1.Ctx(1, true)); found {
		if v, ok := e.Find(asn1.Ctx(1, false)); ok {
			n, _ := v.Int()
			return nil, n, nil
		}
		if v, ok := e.Find(asn1.TagInteger); ok {
			n, _ := v.Int()
			return nil, n, nil
		}
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
			inner := CancelSessionResponseFromTLV(resp)
			out.Reason = inner
		}
	}
	return out, nil
}

func CancelSessionResponseFromTLV(t asn1.TLV) int64 {
	if ok, found := t.Find(asn1.Ctx(0, true)); found {
		kids, err := ok.Children()
		if err == nil {
			for _, k := range kids {
				if len(k.Tag) == 1 && k.Tag[0] == 0x30 {
					if s, err := DecodeEuiccCancelSessionSigned(k); err == nil {
						return s.Reason
					}
				}
			}
		}
	}
	// Error alternative: the error code occupies the reason slot for callers
	// that only need a value.
	if e, found := t.Find(asn1.Ctx(1, false)); found {
		if n, err := e.Int(); err == nil {
			return n
		}
	}
	if e, found := t.Find(asn1.Ctx(1, true)); found {
		if v, ok := e.Find(asn1.Ctx(1, false)); ok {
			if n, err := v.Int(); err == nil {
				return n
			}
		}
	}
	return -1
}
