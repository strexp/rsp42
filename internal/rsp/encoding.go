package rsp

import (
	"encoding/hex"
	"fmt"
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
func LuhnCheckDigit(prefix string) (byte, error) {
	sum := 0
	double := true
	for i := len(prefix) - 1; i >= 0; i-- {
		c := prefix[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("rsp: non-digit %q in %q", c, prefix)
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return byte((10 - sum%10) % 10), nil
}

// LuhnValid reports whether s (including its trailing check digit) is Luhn-valid.
func LuhnValid(s string) bool {
	if len(s) < 2 {
		return false
	}
	digit, err := LuhnCheckDigit(s[:len(s)-1])
	if err != nil {
		return false
	}
	return s[len(s)-1] == '0'+digit
}
