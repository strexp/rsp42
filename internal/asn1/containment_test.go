package asn1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBuilderAPIIsSelfContained pins the seam that lets the BER-TLV library be
// replaced: Tag is a plain byte slice and Builder is this package's own type.
// This file imports nothing from the third-party library, which is the property
// under test: the assertions below only compile while a []byte is accepted
// wherever a tag is expected and the constructors return this package's types.
func TestBuilderAPIIsSelfContained(t *testing.T) {
	// A tag literal is interchangeable with what App/Ctx produce.
	tag := []byte{0xA0}
	require.Equal(t, tag, Ctx(0, true))

	// The constructors accept the plain slice and produce a Builder that Marshal
	// and MarshalBinary encode.
	parent := New(tag, Int(1))
	require.Equal(t, "a003020101", hex.EncodeToString(Marshal(parent)))

	b, err := parent.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, "a003020101", hex.EncodeToString(b))
}
