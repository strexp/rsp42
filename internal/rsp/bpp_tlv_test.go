package rsp

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

// TestTLVBytesSupportsLargeLengths pins why tlvBytes exists: asn1.Marshal (the
// bertlv writer) cannot express a content length above 65535 bytes, while a
// real UPP/BPP can exceed it.
func TestTLVBytesSupportsLargeLengths(t *testing.T) {
	content := bytes.Repeat([]byte{0xAB}, 70000)

	got := tlvBytes(asn1.TagOctetStr, content)
	// OCTET STRING + long-form length 0x011170 (70000).
	require.Equal(t, []byte{0x04, 0x83, 0x01, 0x11, 0x70}, got[:5])

	parsed, rest, err := asn1.ReadTLV(got)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, content, parsed.Value)

	require.Panics(t, func() {
		_ = asn1.Marshal(asn1.Prim(asn1.TagOctetStr, content))
	}, "asn1.Marshal cannot encode more than 64 KiB; tlvBytes must stay")
}

// TestTLVBytesSupportsConstructedContent pins the second reason tlvBytes exists:
// a constructed tag whose content is already encoded, which the bertlv builder
// rejects ("constructed tag cannot have value").
func TestTLVBytesSupportsConstructedContent(t *testing.T) {
	got := tlvBytes(asn1.Ctx(54, true), []byte{0x01, 0x02})
	require.Equal(t, []byte{0xBF, 0x36, 0x02, 0x01, 0x02}, got)

	parsed, _, err := asn1.ReadTLV(got)
	require.NoError(t, err)
	require.True(t, parsed.Constructed)

	require.Panics(t, func() {
		_ = asn1.Prim(asn1.Ctx(54, true), []byte{0x01})
	}, "asn1.Prim cannot build a constructed TLV with a raw value")
}
