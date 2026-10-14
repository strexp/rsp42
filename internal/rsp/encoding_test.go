package rsp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

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
	b, err := EIDBytes(eid)
	require.NoError(t, err)
	require.Len(t, b, 16)
	require.Equal(t, eid, hex.EncodeToString(b))

	_, err = EIDBytes("8904903212345123451234567890123") // 31 digits
	require.Error(t, err)
	_, err = EIDBytes("8904903212345123451234567890123g") // non-digit
	require.Error(t, err)
	_, err = EIDBytes("bad")
	require.Error(t, err)
}
