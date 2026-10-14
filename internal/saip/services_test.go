package saip

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

// TestServiceNamesComplete pins N15: the ServicesList table covers every index
// up to the V2.3.1 maximum (24 entries), the names are unique, and the file-type
// service uses the specification spelling "ber-tlv" (C7).
func TestServiceNamesComplete(t *testing.T) {
	require.Equal(t, "ber-tlv", serviceNames[SvcBERTLV])
	require.Len(t, serviceNames, svcMax+1, "one name per ServicesList index")
	seen := map[string]int{}
	for i := SvcContactless; i <= svcMax; i++ {
		name, ok := serviceNames[i]
		require.True(t, ok, "index %d has no name", i)
		require.NotEmpty(t, name)
		_, dup := seen[name]
		require.False(t, dup, "duplicate service name %q", name)
		seen[name] = i
	}
}

// TestServicesIncludesV231Additions verifies that the five entries added by
// SAIP V2.3.1 are visible in the decoded services list.
func TestServicesIncludesV231Additions(t *testing.T) {
	h := &Header{Node: asn1.NewConstructed(TagHeader)}
	for _, idx := range []int{SvcDFLink, SvcCATTp, SvcGetIdentity, SvcProfileAX25519, SvcProfileBP256} {
		h.SetService(idx, true)
	}
	require.Equal(t,
		[]string{"dfLink", "cat-tp", "get-identity", "profile-a-x25519", "profile-b-p256"},
		h.Services())
}

// buildAKASequence builds the minimal PE sequence RebuildMandatoryServices needs
// to derive the AKA service bits: a ProfileHeader plus a PE-AKAParameter whose
// algorithmID is 2 (TUAK) and whose K has the given length.
func buildAKASequence(keyLen int) *Sequence {
	hdr := asn1.NewConstructed(TagHeader,
		asn1.NewPrimitive(hdrMajor, []byte{2}),
		asn1.NewPrimitive(hdrMinor, []byte{3}),
	)
	algo := asn1.NewConstructed(asn1.Ctx(1, true),
		asn1.NewPrimitive(asn1.Ctx(0, false), []byte{2}),
		asn1.NewPrimitive(asn1.Ctx(2, false), make([]byte, keyLen)),
	)
	cfg := asn1.NewConstructed(asn1.Ctx(1, true), algo)
	aka := asn1.NewConstructed(TagAKAParameter, cfg)
	return &Sequence{Elements: []*asn1.Node{hdr, aka}}
}

// TestRebuildMandatoryServicesTUAKKeyLength pins the TUAK-256 fix: algorithm id
// 2 means TUAK, and the key length (16 vs 32 bytes) selects TUAK-128 vs
// TUAK-256. Previously SvcTUAK256 was declared but never set.
func TestRebuildMandatoryServicesTUAKKeyLength(t *testing.T) {
	seq := buildAKASequence(32)
	require.Equal(t, 32, AKAKeyLength(seq.Find(TagAKAParameter)))
	require.NoError(t, seq.RebuildMandatoryServices())
	h, err := ParseHeader(seq.Header())
	require.NoError(t, err)
	require.Contains(t, h.Services(), "tuak256")
	require.NotContains(t, h.Services(), "tuak128")

	seq = buildAKASequence(16)
	require.NoError(t, seq.RebuildMandatoryServices())
	h, err = ParseHeader(seq.Header())
	require.NoError(t, err)
	require.Contains(t, h.Services(), "tuak128")
	require.NotContains(t, h.Services(), "tuak256")
}
