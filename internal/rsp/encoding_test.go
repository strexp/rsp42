package rsp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNibbleSwap(t *testing.T) {
	require.Equal(t, []byte{0x21, 0x43}, NibbleSwap([]byte{0x12, 0x34}))
}

func TestICCIDBCD(t *testing.T) {
	// 19-digit ICCID with 0xF padding.
	iccid := "8900012345678901234"
	bcd, err := DigitsToBCD(iccid)
	require.NoError(t, err)
	require.Len(t, bcd, 10)
	require.Equal(t, "980010325476981032f4", hex.EncodeToString(bcd))
	require.Equal(t, iccid, BCDToDigits(bcd))

	// 20-digit ICCID, no padding.
	iccid20 := "89000123456789012341"
	bcd20, err := DigitsToBCD(iccid20)
	require.NoError(t, err)
	require.Len(t, bcd20, 10)
	require.Equal(t, iccid20, BCDToDigits(bcd20))
}

func TestICCIDTwoEncodings(t *testing.T) {
	iccid := "89000123456789012341"

	header, err := ICCIDHeaderBytes(iccid)
	require.NoError(t, err)
	require.Equal(t, "89000123456789012341", hex.EncodeToString(header))
	require.Equal(t, iccid, ICCIDFromHeaderBytes(header))

	ef, err := ICCIDEFBytes(iccid)
	require.NoError(t, err)
	require.Equal(t, "98001032547698103214", hex.EncodeToString(ef))
	require.Equal(t, iccid, ICCIDFromEFBytes(ef))
}

func TestLuhn(t *testing.T) {
	// Well-known Luhn example: 79927398713 is valid.
	require.True(t, LuhnValid("79927398713"))
	require.False(t, LuhnValid("79927398710"))
	d, err := LuhnCheckDigit("7992739871")
	require.NoError(t, err)
	require.Equal(t, byte('3'), '0'+d)
}

func TestEID(t *testing.T) {
	eid := "89049032123451234512345678901235"
	require.True(t, ValidEID(eid))
	b, err := EIDBytes(eid)
	require.NoError(t, err)
	require.Len(t, b, 16)
	require.Equal(t, eid, EIDString(b))

	require.False(t, ValidEID("8904903212345123451234567890123"))  // 31 digits
	require.False(t, ValidEID("8904903212345123451234567890123g")) // non-digit
	_, err = EIDBytes("bad")
	require.Error(t, err)
}
