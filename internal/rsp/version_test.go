package rsp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

func TestVersionParseAndCompare(t *testing.T) {
	v, err := ParseVersion("2.3.1")
	require.NoError(t, err)
	require.Equal(t, Version{Major: 2, Minor: 3}, v, "a document revision is ignored")
	require.Equal(t, "2.3", v.String())

	require.Equal(t, -1, Version{2, 1}.Compare(Version{2, 3}))
	require.Equal(t, 1, Version{3, 0}.Compare(Version{2, 9}))
	require.Equal(t, 0, Version{2, 3}.Compare(Version{2, 3}))

	for _, bad := range []string{"", "2", "x.1", "2.y", "2.3.1.4"} {
		_, err := ParseVersion(bad)
		require.Error(t, err, "input %q", bad)
	}
}

// TestEUICCInfo2AdditionalVersions pins N11: the optional
// additionalEuiccProfilePackageVersions list (SGP.22 v2.7 §5.7.6, tag [15]) is
// parsed and folded into the supported version set.
func TestEUICCInfo2AdditionalVersions(t *testing.T) {
	raw := asn1.Marshal(asn1.New(asn1.Ctx(34, true), // [34] EUICCInfo2, tag BF22
		asn1.Prim(asn1.Ctx(1, false), []byte{0x02, 0x03, 0x00}), // profileVersion 2.3
		asn1.Prim(asn1.Ctx(2, false), []byte{0x02, 0x07, 0x00}), // svn
		asn1.Prim(asn1.Ctx(5, false), []byte{0x00, 0x40}),       // uiccCapability
		asn1.New(asn1.Ctx(15, true), // additionalEuiccProfilePackageVersions
			asn1.Octet([]byte{0x03, 0x02, 0x00}),
			asn1.Octet([]byte{0x03, 0x01, 0x00}),
		),
	))
	info, err := ParseEUICCInfo2(raw)
	require.NoError(t, err)

	base, ok := info.ProfilePackageVersion()
	require.True(t, ok)
	require.Equal(t, Version{Major: 2, Minor: 3}, base)

	supported := info.SupportedVersions()
	require.Contains(t, supported, Version{Major: 2, Minor: 3})
	require.Contains(t, supported, Version{Major: 3, Minor: 2})
	require.Contains(t, supported, Version{Major: 3, Minor: 1})
	require.True(t, info.IsV3Capable())
	require.Equal(t, []byte{0x00, 0x40}, info.UICCCapability)
}

// TestEUICCInfo2WithoutAdditionalVersions is the V2-only eUICC: no [15] field,
// so the supported set is just profileVersion and V3 capability is false.
func TestEUICCInfo2WithoutAdditionalVersions(t *testing.T) {
	raw := asn1.Marshal(asn1.New(asn1.Ctx(34, true),
		asn1.Prim(asn1.Ctx(1, false), []byte{0x02, 0x01, 0x00}),
		asn1.Prim(asn1.Ctx(2, false), []byte{0x02, 0x07, 0x00}),
	))
	info, err := ParseEUICCInfo2(raw)
	require.NoError(t, err)
	require.Equal(t, []Version{{Major: 2, Minor: 1}}, info.SupportedVersions())
	require.False(t, info.IsV3Capable())
}
