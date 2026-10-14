// Package rsp implements the SGP.22 RSP message structures and codecs.
//
// The encodings follow the RSPDefinitions ASN.1 module (AUTOMATIC TAGS,
// EXTENSIBILITY IMPLIED). The automatic-tag assignments were cross-checked
// byte-for-byte against asn1tools and the gomaja-generated bindings (see
// testdata/vectors/rsp_golden.json); note in particular that a few untagged
// fields remain universal (e.g. SmdpSigned2.ccRequiredFlag,
// NotificationMetadata.notificationAddress).
package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// Child lookup helpers ------------------------------------------------------

func childBytes(t asn1.TLV, tag []byte) []byte {
	c, ok := t.Find(tag)
	if !ok {
		return nil
	}
	return c.Value
}

func childString(t asn1.TLV, tag []byte) string {
	c, ok := t.Find(tag)
	if !ok {
		return ""
	}
	return string(c.Value)
}

// ServerSigned1 -------------------------------------------------------------

// ServerSigned1 is the data object signed by SK.DPauth (SGP.22 §5.7.13).
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
type EUICCInfo1 struct {
	Raw                       []byte
	SVN                       []byte
	CiPKIDListForVerification [][]byte
	CiPKIDListForSigning      [][]byte
	CiPKIDListForSigningV3    [][]byte
}

// ParseEUICCInfo1 parses a EUICCInfo1 (BF20) data object.
func ParseEUICCInfo1(raw []byte) (*EUICCInfo1, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, fmt.Errorf("rsp: parse EUICCInfo1: %w", err)
	}
	if hex.EncodeToString(t.Tag) != "bf20" {
		return nil, fmt.Errorf("rsp: EUICCInfo1 unexpected tag %X", t.Tag)
	}
	info := &EUICCInfo1{Raw: t.Raw, SVN: childBytes(t, asn1.Ctx(2, false))}
	if v, ok := t.Find(asn1.Ctx(9, true)); ok {
		info.CiPKIDListForVerification = octetList(v)
	}
	if v, ok := t.Find(asn1.Ctx(10, true)); ok {
		info.CiPKIDListForSigning = octetList(v)
	}
	if v, ok := t.Find(asn1.Ctx(11, true)); ok { // V3 list, when present
		info.CiPKIDListForSigningV3 = octetList(v)
	}
	return info, nil
}

// EUICCInfo2 carries the eUICC capabilities (SGP.22 §5.7.6).
type EUICCInfo2 struct {
	Raw                       []byte
	ProfileVersion            []byte
	SVN                       []byte
	CiPKIDListForVerification [][]byte
	CiPKIDListForSigning      [][]byte
	PPVersion                 []byte
	SASAcreditationNumber     string
	// AdditionalEuiccProfilePackageVersions lists the higher-major SAIP
	// packages the eUICC also supports (SGP.22 v2.7 §5.7.6, tag [15]). The
	// field is present only when a major version above ProfileVersion is
	// supported, so its presence marks a "V3-capable" eUICC.
	AdditionalEuiccProfilePackageVersions [][]byte
	// UICCCapability is the raw uiccCapability BIT STRING content ([5]).
	UICCCapability []byte
}

// ParseEUICCInfo2 parses a EUICCInfo2 (BF22) data object.
func ParseEUICCInfo2(raw []byte) (*EUICCInfo2, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, fmt.Errorf("rsp: parse EUICCInfo2: %w", err)
	}
	if hex.EncodeToString(t.Tag) != "bf22" {
		return nil, fmt.Errorf("rsp: EUICCInfo2 unexpected tag %X", t.Tag)
	}
	info := &EUICCInfo2{
		Raw:            t.Raw,
		ProfileVersion: childBytes(t, asn1.Ctx(1, false)),
		SVN:            childBytes(t, asn1.Ctx(2, false)),
	}
	if v, ok := t.Find(asn1.Ctx(9, true)); ok {
		info.CiPKIDListForVerification = octetList(v)
	}
	if v, ok := t.Find(asn1.Ctx(10, true)); ok {
		info.CiPKIDListForSigning = octetList(v)
	}
	if v, ok := t.Find(asn1.Ctx(15, true)); ok {
		info.AdditionalEuiccProfilePackageVersions = octetList(v)
	}
	if v, ok := t.Find(asn1.Ctx(5, false)); ok {
		info.UICCCapability = v.Value
	}
	// ppVersion and sasAcreditationNumber are untagged (universal tags).
	info.PPVersion = childBytes(t, []byte{0x04})
	info.SASAcreditationNumber = childString(t, []byte{0x0c})
	return info, nil
}

// ProfilePackageVersion returns the base SAIP version the eUICC declares.
func (i *EUICCInfo2) ProfilePackageVersion() (Version, bool) {
	return VersionFromBytes(i.ProfileVersion)
}

// SupportedVersions returns every SAIP version the eUICC declares support for:
// profileVersion plus the additionalEuiccProfilePackageVersions list. Versions
// are compared by (major, minor) only.
func (i *EUICCInfo2) SupportedVersions() []Version {
	var out []Version
	seen := map[Version]bool{}
	add := func(b []byte) {
		v, ok := VersionFromBytes(b)
		if !ok || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	add(i.ProfileVersion)
	for _, b := range i.AdditionalEuiccProfilePackageVersions {
		add(b)
	}
	return out
}

// IsV3Capable reports whether the eUICC declares support for a SAIP v3 package.
func (i *EUICCInfo2) IsV3Capable() bool {
	for _, v := range i.SupportedVersions() {
		if v.Major >= 3 {
			return true
		}
	}
	return false
}

func octetList(t asn1.TLV) [][]byte {
	kids, err := t.Children()
	if err != nil {
		return nil
	}
	var out [][]byte
	for _, k := range kids {
		out = append(out, k.Value)
	}
	return out
}

// DeviceInfo / CtxParams ----------------------------------------------------

// DeviceInfo describes the requesting device (SGP.22 §5.7.13).
type DeviceInfo struct {
	TAC  []byte
	IMEI []byte
	Raw  []byte
}

// ParseDeviceInfo parses a DeviceInfo (implicit tag [1]) TLV.
func ParseDeviceInfo(t asn1.TLV) *DeviceInfo {
	return &DeviceInfo{
		TAC:  childBytes(t, asn1.Ctx(0, false)),
		IMEI: childBytes(t, asn1.Ctx(2, false)),
		Raw:  t.Raw,
	}
}

// CtxParamsForCommonAuthentication carries the MatchingID and device info.
type CtxParamsForCommonAuthentication struct {
	MatchingID string
	DeviceInfo *DeviceInfo
}

// ParseCtxParams1 parses a CtxParams1 CHOICE (A0 wrapping).
func ParseCtxParams1(t asn1.TLV) (*CtxParamsForCommonAuthentication, error) {
	if len(t.Tag) != 1 || t.Tag[0] != 0xa0 {
		return nil, fmt.Errorf("rsp: CtxParams1 unexpected tag %X", t.Tag)
	}
	out := &CtxParamsForCommonAuthentication{}
	if v, ok := t.Find(asn1.Ctx(0, false)); ok {
		out.MatchingID = string(v.Value)
	}
	if v, ok := t.Find(asn1.Ctx(1, true)); ok {
		out.DeviceInfo = ParseDeviceInfo(v)
	}
	return out, nil
}

// EuiccSigned1 --------------------------------------------------------------

// EuiccSigned1 is the eUICC-signed data object (SGP.22 §5.7.13).
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
	if ok, found := t.Find(asn1.Ctx(0, true)); found {
		kids, err := ok.Children()
		if err != nil {
			return nil, nil, err
		}
		out := &PrepareDownloadResponseOk{}
		for _, k := range kids {
			switch {
			case len(k.Tag) == 1 && k.Tag[0] == 0x30 && out.EuiccSigned2 == nil:
				out.EuiccSigned2Raw = k.Raw
				out.EuiccSigned2, err = DecodeEUICCSigned2(k)
				if err != nil {
					return nil, nil, err
				}
			case len(k.Tag) == 2 && k.Tag[0] == 0x5f && k.Tag[1] == 0x37:
				out.EuiccSignature2 = k.Value
			}
		}
		return out, nil, nil
	}
	if e, found := t.Find(asn1.Ctx(1, true)); found {
		errResp := &PrepareDownloadResponseError{TransactionID: childBytes(e, asn1.Ctx(0, false))}
		if v, ok := e.Find(asn1.TagInteger); ok {
			errResp.DownloadErrorCode, _ = v.Int()
		}
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
	if ok, found := t.Find(asn1.Ctx(0, true)); found {
		kids, err := ok.Children()
		if err != nil {
			return nil, nil, err
		}
		out := &AuthenticateResponseOk{}
		var certs [][]byte
		for _, k := range kids {
			switch {
			case len(k.Tag) == 1 && k.Tag[0] == 0x30 && out.EuiccSigned1 == nil:
				out.EuiccSigned1, err = DecodeEuiccSigned1(k)
				if err != nil {
					return nil, nil, err
				}
			case len(k.Tag) == 2 && k.Tag[0] == 0x5f && k.Tag[1] == 0x37:
				out.EuiccSignature1 = k.Value
			case len(k.Tag) == 1 && k.Tag[0] == 0x30:
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
	}
	if e, found := t.Find(asn1.Ctx(1, true)); found {
		errResp := &AuthenticateResponseError{TransactionID: childBytes(e, asn1.Ctx(0, false))}
		if v, ok := e.Find(asn1.TagInteger); ok {
			errResp.AuthenticateErrorCode, _ = v.Int()
		}
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
