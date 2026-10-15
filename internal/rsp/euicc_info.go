package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

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
	// ForbiddenProfilePolicyRules is the PprIds bitmap ([25]) of the rules the
	// eUICC declares 'forbidden' (SGP.22 §5.7.5). The SM-DP+ SHALL not deliver a
	// Profile carrying one of them. It is stored without the BIT STRING
	// unused-bits octet, like Profile.PPRIds.
	ForbiddenProfilePolicyRules []byte
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
	// forbiddenProfilePolicyRules is a BIT STRING, so its value starts with the
	// unused-bits octet.
	if v, ok := t.Find(asn1.Ctx(25, false)); ok {
		info.ForbiddenProfilePolicyRules = PPRBitStringContent(v.Value)
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
