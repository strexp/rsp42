// Package iccid holds ICCID text helpers shared by the persistence layer, the
// services and the SAIP personalization engine.
//
// It is a leaf package on purpose: validating an ICCID check digit or stripping
// its padding nibble must not require importing the SGP.22 wire codec, which is
// what the persistence layer used to do (docs/refactoring-plan.md 阶段 3).
package iccid

import "fmt"

// Normalize strips the trailing 'F' padding nibbles of a BCD-padded ICCID
// (SGP.22 §5.7.2 / 3GPP TS 23.003). It does not validate. This matches the
// previous strings.TrimRight(s, "fF") behaviour, including the case of several
// padding nibbles.
func Normalize(s string) string {
	n := len(s)
	for n > 0 && (s[n-1] == 'f' || s[n-1] == 'F') {
		n--
	}
	return s[:n]
}

// Canonical normalizes and validates an operator-supplied ICCID: the trailing
// 'F' padding is removed, and what remains must be 19 or 20 decimal digits with
// a valid Luhn check digit.
func Canonical(s string) (string, error) {
	s = Normalize(s)
	if len(s) != 19 && len(s) != 20 {
		return "", fmt.Errorf("iccid: %q must be 19 or 20 digits", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", fmt.Errorf("iccid: %q contains a non-digit", s)
		}
	}
	if !LuhnValid(s) {
		return "", fmt.Errorf("iccid: %q has an invalid check digit", s)
	}
	return s, nil
}

// LuhnCheckDigit returns the Luhn check digit for the given numeric prefix.
func LuhnCheckDigit(prefix string) (byte, error) {
	sum := 0
	double := true
	for i := len(prefix) - 1; i >= 0; i-- {
		c := prefix[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("iccid: non-digit %q in %q", c, prefix)
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

// LuhnValid reports whether s (including its trailing check digit) is
// Luhn-valid.
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
