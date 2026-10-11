package asn1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTagEncoding(t *testing.T) {
	require.Equal(t, "bf36", hex.EncodeToString(Ctx(0x36, true)))
	require.Equal(t, "bf20", hex.EncodeToString(Ctx(0x20, true)))
	require.Equal(t, "5f37", hex.EncodeToString(App(0x37, false)))
	require.Equal(t, "5f49", hex.EncodeToString(App(0x49, false)))
	require.Equal(t, "87", hex.EncodeToString(Ctx(7, false)))
	require.Equal(t, "a0", hex.EncodeToString(Ctx(0, true)))
}

func TestReadTLVRawExtraction(t *testing.T) {
	// A realistic BPP-like shell with a context-tagged OCTET STRING.
	seg := Prim(Ctx(7, false), []byte{0xde, 0xad, 0xbe, 0xef})
	a0 := New(Ctx(0, true), seg)
	bpp := New(Ctx(0x36, true), New(Ctx(0x23, true), Int(1), Octet([]byte{1, 2, 3})), a0)

	wire := Marshal(bpp)
	outer, rest, err := ReadTLV(wire)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, wire, outer.Raw)
	require.Equal(t, "bf36", hex.EncodeToString(outer.Tag))

	kids, err := outer.Children()
	require.NoError(t, err)
	require.Len(t, kids, 2)

	a0Parsed, ok := outer.Find([]byte{0xa0})
	require.True(t, ok)
	s87, ok := a0Parsed.Find([]byte{0x87})
	require.True(t, ok)
	require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, s87.Value)
	// The raw slice must be a view into the original buffer.
	require.Equal(t, "8704deadbeef", hex.EncodeToString(s87.Raw))
}

func TestMultipleTLVs(t *testing.T) {
	wire := append(Marshal(Int(1)), Marshal(Octet([]byte("hi")))...)
	tlvs, err := ReadTLVs(wire)
	require.NoError(t, err)
	require.Len(t, tlvs, 2)
	v, err := tlvs[0].Int()
	require.NoError(t, err)
	require.EqualValues(t, 1, v)
	require.Equal(t, "hi", string(tlvs[1].Value))
}

func TestIntRoundTrip(t *testing.T) {
	cases := []int64{0, 1, 127, 128, 255, 256, 65535, 1 << 20, -1, -128, -129, -32768}
	for _, want := range cases {
		t.Run(hex.EncodeToString(encodeInt(want)), func(t *testing.T) {
			parsed, _, err := ReadTLV(Marshal(Int(want)))
			require.NoError(t, err)
			got, err := parsed.Int()
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
	// Minimal encoding checks.
	require.Equal(t, "00", hex.EncodeToString(encodeInt(0)))
	require.Equal(t, "7f", hex.EncodeToString(encodeInt(127)))
	require.Equal(t, "0080", hex.EncodeToString(encodeInt(128)))
	require.Equal(t, "ff", hex.EncodeToString(encodeInt(-1)))
	require.Equal(t, "80", hex.EncodeToString(encodeInt(-128)))
	require.Equal(t, "ff7f", hex.EncodeToString(encodeInt(-129)))
}

func TestOIDRoundTrip(t *testing.T) {
	for _, oid := range []string{"2.23.146.1.2.1.4", "2.999.10", "1.2.840.113549.1.1.11", "2.23.146.1.2.2.0"} {
		enc := EncodeOID(oid)
		got, err := DecodeOID(enc)
		require.NoError(t, err)
		require.Equal(t, oid, got)
	}
}

func TestBitString(t *testing.T) {
	// NotificationEvent with bit 0 (install) set.
	parsed, _, err := ReadTLV(Marshal(BitString(0, []byte{0x80})))
	require.NoError(t, err)
	unused, bits, err := parsed.BitString()
	require.NoError(t, err)
	require.EqualValues(t, 0, unused)
	require.Equal(t, []byte{0x80}, bits)
	set, err := parsed.BitSet(0)
	require.NoError(t, err)
	require.True(t, set)
	set, err = parsed.BitSet(1)
	require.NoError(t, err)
	require.False(t, set)

	require.Equal(t, "03020080", hex.EncodeToString(parsed.Raw))
}

func TestReadHeaderLenient(t *testing.T) {
	// A BSP segment after MAC removal: the declared length still counts the
	// MAC, so ReadHeader must not require the full content.
	payload := []byte{0x87, 0x18, 1, 2, 3}
	tag, hdr, err := ReadHeader(payload)
	require.NoError(t, err)
	require.Equal(t, []byte{0x87}, tag)
	require.Equal(t, 2, hdr)
}

func TestEncodeLengthBoundaries(t *testing.T) {
	require.Equal(t, "7f", hex.EncodeToString(EncodeLength(0x7f)))
	require.Equal(t, "8180", hex.EncodeToString(EncodeLength(0x80)))
	require.Equal(t, "81ff", hex.EncodeToString(EncodeLength(0xff)))
	require.Equal(t, "820100", hex.EncodeToString(EncodeLength(0x100)))
	require.Equal(t, "8203fc", hex.EncodeToString(EncodeLength(1020)))
}

func TestSeqUnmarshal(t *testing.T) {
	msg := Seq(Int(5), Bool(true), UTF8("abc"), Null())
	wire := Marshal(msg)
	parsed, _, err := ReadTLV(wire)
	require.NoError(t, err)
	kids, err := parsed.Children()
	require.NoError(t, err)
	require.Len(t, kids, 4)
	require.Equal(t, "02", hex.EncodeToString(kids[0].Tag))
}
