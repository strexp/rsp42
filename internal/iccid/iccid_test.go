package iccid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	require.Equal(t, "8900012345678901234", Normalize("8900012345678901234"))
	require.Equal(t, "8900012345678901234", Normalize("8900012345678901234F"))
	require.Equal(t, "8900012345678901234", Normalize("8900012345678901234f"))
	require.Equal(t, "8900012345678901234", Normalize("8900012345678901234FF"),
		"BCD padding may be more than one nibble")
	require.Equal(t, "", Normalize(""))
	require.Equal(t, "", Normalize("FF"))
}

func TestLuhn(t *testing.T) {
	// Well-known Luhn example: 79927398713 is valid.
	require.True(t, LuhnValid("79927398713"))
	require.False(t, LuhnValid("79927398710"))
	d, err := LuhnCheckDigit("7992739871")
	require.NoError(t, err)
	require.Equal(t, byte('3'), '0'+d)

	// Too short to carry a check digit.
	require.False(t, LuhnValid(""))
	require.False(t, LuhnValid("7"))

	_, err = LuhnCheckDigit("12a4")
	require.Error(t, err)
}

func TestCanonical(t *testing.T) {
	// A valid 19-digit ICCID with its BCD padding nibble.
	good, err := Canonical("8900012345678901230F")
	require.NoError(t, err)
	require.Equal(t, "8900012345678901230", good)

	// A valid 20-digit ICCID.
	good20, err := Canonical("89000123456789012341")
	require.NoError(t, err)
	require.Equal(t, "89000123456789012341", good20)
	require.True(t, LuhnValid(good20))

	for _, bad := range []string{
		"",
		"890001234567890123",    // 18 digits
		"890001234567890123456", // 21 digits
		"890001234567890123a",   // non-digit
		"89000123456789012340",  // wrong check digit
		"F",                     // nothing left after padding
	} {
		_, err := Canonical(bad)
		require.Error(t, err, "input %q", bad)
	}
}

func TestDecodeBCD(t *testing.T) {
	// Nibble-swapped BCD: the low nibble of each byte is the leading digit.
	require.Equal(t, "89012345678901234567",
		DecodeBCD([]byte{0x98, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0x76}))
	// A 19-digit ICCID pads the last nibble with 'F', which is dropped.
	require.Equal(t, "8901234567890123456",
		DecodeBCD([]byte{0x98, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xF6}))
	// A padded trailing byte decodes to "890F", whose trailing padding is dropped.
	require.Equal(t, "890", DecodeBCD([]byte{0x98, 0xf0}))
	require.Equal(t, "", DecodeBCD(nil))
	require.Equal(t, "", DecodeBCD([]byte{0xFF}))
}
