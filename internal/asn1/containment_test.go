package asn1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBuilderAPIIsSelfContained pins the seam that lets the BER-TLV library be
// replaced: Tag is a plain byte slice and Builder is this package's own type, so
// no caller (and no file here except construct.go) needs the third-party type.
func TestBuilderAPIIsSelfContained(t *testing.T) {
	var tag Tag = Ctx(0, true)
	var child *Builder = Int(1)
	var parent *Builder = New(tag, child)

	// A plain []byte is assignable to Tag, and Tag is assignable to []byte.
	var raw []byte = tag
	require.Equal(t, []byte{0xA0}, raw)

	require.Equal(t, "a003020101", hex.EncodeToString(Marshal(parent)))

	// The wrapper implements encoding.BinaryMarshaler like the underlying value.
	b, err := parent.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, "a003020101", hex.EncodeToString(b))
}
