package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/iccid"
)

// EIDBytes converts a 32-digit EID string into its 16-byte binary form (the
// digits are taken in order, two per byte).
func EIDBytes(eid string) ([]byte, error) {
	if len(eid) != 32 {
		return nil, fmt.Errorf("rsp: invalid EID %q", eid)
	}
	for i := 0; i < len(eid); i++ {
		if eid[i] < '0' || eid[i] > '9' {
			return nil, fmt.Errorf("rsp: invalid EID %q", eid)
		}
	}
	return hex.DecodeString(eid)
}

// LuhnCheckDigit returns the Luhn check digit for the given numeric prefix.
// The implementation lives in internal/iccid; this is a deprecated alias kept
// for callers that still import the codec package (they migrate to iccid.
func LuhnCheckDigit(prefix string) (byte, error) { return iccid.LuhnCheckDigit(prefix) }

// LuhnValid reports whether s (including its trailing check digit) is
// Luhn-valid. Deprecated alias for iccid.LuhnValid.
func LuhnValid(s string) bool { return iccid.LuhnValid(s) }
