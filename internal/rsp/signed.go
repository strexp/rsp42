package rsp

import (
	"fmt"

	"rsp42/internal/asn1"
)

type ServerSigned1 struct {
	TransactionID   []byte
	EuiccChallenge  []byte
	ServerAddress   string
	ServerChallenge []byte
}

// Encode returns the DER/BER encoding of ServerSigned1.
func (s *ServerSigned1) Encode() []byte {
	return asn1.Marshal(asn1.Seq(
		asn1.Prim(asn1.Ctx(0, false), s.TransactionID),
		asn1.Prim(asn1.Ctx(1, false), s.EuiccChallenge),
		asn1.Prim(asn1.Ctx(3, false), []byte(s.ServerAddress)),
		asn1.Prim(asn1.Ctx(4, false), s.ServerChallenge),
	))
}

// DecodeServerSigned1 parses a ServerSigned1 TLV.
func DecodeServerSigned1(t asn1.TLV) (*ServerSigned1, error) {
	s := &ServerSigned1{
		TransactionID:   childBytes(t, asn1.Ctx(0, false)),
		EuiccChallenge:  childBytes(t, asn1.Ctx(1, false)),
		ServerAddress:   childString(t, asn1.Ctx(3, false)),
		ServerChallenge: childBytes(t, asn1.Ctx(4, false)),
	}
	if s.TransactionID == nil || s.ServerChallenge == nil {
		return nil, fmt.Errorf("rsp: ServerSigned1 missing required fields")
	}
	return s, nil
}

// EUICCInfo ----------------------------------------------------------------

// EUICCInfo1 carries the eUICC SGP.22 version and CI key lists (SGP.22 §5.7.2).

type EuiccSigned1 struct {
	TransactionID   []byte
	ServerAddress   string
	ServerChallenge []byte
	EuiccInfo2      *EUICCInfo2
	CtxParams1      *CtxParamsForCommonAuthentication
}

// DecodeEuiccSigned1 parses a EuiccSigned1 TLV.
func DecodeEuiccSigned1(t asn1.TLV) (*EuiccSigned1, error) {
	s := &EuiccSigned1{
		TransactionID:   childBytes(t, asn1.Ctx(0, false)),
		ServerAddress:   childString(t, asn1.Ctx(3, false)),
		ServerChallenge: childBytes(t, asn1.Ctx(4, false)),
	}
	if s.TransactionID == nil {
		return nil, fmt.Errorf("rsp: EuiccSigned1 missing transactionId")
	}
	if v, ok := t.Find([]byte{0xbf, 0x22}); ok {
		info, err := ParseEUICCInfo2(v.Raw)
		if err != nil {
			return nil, err
		}
		s.EuiccInfo2 = info
	}
	if v, ok := t.Find([]byte{0xa0}); ok {
		cp, err := ParseCtxParams1(v)
		if err != nil {
			return nil, err
		}
		s.CtxParams1 = cp
	}
	return s, nil
}

// SmdpSigned2 ---------------------------------------------------------------

// SmdpSigned2 is the SM-DP+-signed data object (SGP.22 §5.7.4).
type SmdpSigned2 struct {
	TransactionID  []byte
	CCRequiredFlag bool
	BppEuiccOtpk   []byte
}

// Encode returns the DER/BER encoding of SmdpSigned2.
func (s *SmdpSigned2) Encode() []byte {
	children := []*asn1.Builder{
		asn1.Prim(asn1.Ctx(0, false), s.TransactionID),
		asn1.Bool(s.CCRequiredFlag),
	}
	if len(s.BppEuiccOtpk) > 0 {
		children = append(children, asn1.Prim(asn1.App(73, false), s.BppEuiccOtpk))
	}
	return asn1.Marshal(asn1.Seq(children...))
}

// DecodeSmdpSigned2 parses a SmdpSigned2 TLV.
func DecodeSmdpSigned2(t asn1.TLV) (*SmdpSigned2, error) {
	s := &SmdpSigned2{
		TransactionID: childBytes(t, asn1.Ctx(0, false)),
		BppEuiccOtpk:  childBytes(t, asn1.App(73, false)),
	}
	if v, ok := t.Find(asn1.TagBoolean); ok {
		b, err := v.Bool()
		if err != nil {
			return nil, err
		}
		s.CCRequiredFlag = b
	}
	return s, nil
}

// EUICCSigned2 --------------------------------------------------------------

// EUICCSigned2 is the eUICC-signed data object from PrepareDownload (SGP.22 §5.7.4).
type EUICCSigned2 struct {
	TransactionID []byte
	EuiccOtpk     []byte
	HashCc        []byte
}

// DecodeEUICCSigned2 parses a EUICCSigned2 TLV.
func DecodeEUICCSigned2(t asn1.TLV) (*EUICCSigned2, error) {
	s := &EUICCSigned2{
		TransactionID: childBytes(t, asn1.Ctx(0, false)),
		EuiccOtpk:     childBytes(t, asn1.App(73, false)),
		HashCc:        childBytes(t, asn1.Ctx(2, false)),
	}
	if s.TransactionID == nil || len(s.EuiccOtpk) == 0 {
		return nil, fmt.Errorf("rsp: EUICCSigned2 missing required fields")
	}
	return s, nil
}

// PrepareDownloadResponses --------------------------------------------------

// PrepareDownloadResponseOk is the OK branch of PrepareDownloadResponse.
