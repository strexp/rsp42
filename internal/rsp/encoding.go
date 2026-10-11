package rsp

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// NibbleSwap swaps the high and low nibble of every byte.
func NibbleSwap(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = v>>4 | v<<4
	}
	return out
}

// BCDToDigits decodes nibble-swapped BCD into a digit string, dropping a
// trailing 0xF padding nibble.
func BCDToDigits(b []byte) string {
	var sb strings.Builder
	for i, v := range b {
		lo, hi := v&0x0f, v>>4
		sb.WriteByte(nibbleToDigit(lo))
		if i == len(b)-1 && hi == 0x0f {
			break
		}
		sb.WriteByte(nibbleToDigit(hi))
	}
	return sb.String()
}

// DigitsToBCD encodes a digit string as nibble-swapped BCD (the 3GPP ICCID
// representation), padding the final nibble with 0xF when the digit count is
// odd.
func DigitsToBCD(s string) ([]byte, error) {
	digits := make([]byte, 0, len(s)+1)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("rsp: non-digit %q in %q", c, s)
		}
		digits = append(digits, c-'0')
	}
	if len(digits)%2 != 0 {
		digits = append(digits, 0x0f)
	}
	out := make([]byte, len(digits)/2)
	for i := 0; i < len(out); i++ {
		out[i] = digits[2*i] | digits[2*i+1]<<4
	}
	return out, nil
}

func nibbleToDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'f'
}

// EIDBytes converts a 32-digit EID string into its 16-byte binary form (the
// digits are taken in order, two per byte).
func EIDBytes(eid string) ([]byte, error) {
	if !ValidEID(eid) {
		return nil, fmt.Errorf("rsp: invalid EID %q", eid)
	}
	return hex.DecodeString(eid)
}

// EIDString converts a binary EID back into its 32-digit string form.
func EIDString(b []byte) string { return hex.EncodeToString(b) }

// ValidEID reports whether s is a syntactically valid EID: 32 decimal digits.
func ValidEID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ICCIDHeaderBytes encodes an ICCID for ProfileHeader.iccid: the digit string
// is right-padded with 'F' to 20 characters and taken as plain BCD (no nibble
// swap), yielding 10 bytes.
func ICCIDHeaderBytes(iccid string) ([]byte, error) {
	if err := validateICCIDDigits(iccid); err != nil {
		return nil, err
	}
	padded := iccid
	for len(padded) < 20 {
		padded += "F"
	}
	return hex.DecodeString(padded)
}

// ICCIDFromHeaderBytes decodes ProfileHeader.iccid, dropping a trailing 'F'
// padding nibble.
func ICCIDFromHeaderBytes(b []byte) string {
	s := hex.EncodeToString(b)
	s = strings.TrimRight(s, "fF")
	return s
}

// ICCIDEFBytes encodes an ICCID for EF.ICCID / StoreMetadataRequest.iccid using
// the 3GPP nibble-swapped representation.
func ICCIDEFBytes(iccid string) ([]byte, error) {
	if err := validateICCIDDigits(iccid); err != nil {
		return nil, err
	}
	return DigitsToBCD(iccid)
}

// ICCIDFromEFBytes decodes a 3GPP nibble-swapped ICCID.
func ICCIDFromEFBytes(b []byte) string { return BCDToDigits(b) }

func validateICCIDDigits(iccid string) error {
	if len(iccid) < 1 || len(iccid) > 20 {
		return fmt.Errorf("rsp: ICCID length %d out of range [1,20]", len(iccid))
	}
	for i := 0; i < len(iccid); i++ {
		c := iccid[i]
		if (c < '0' || c > '9') && c != 'f' && c != 'F' {
			return fmt.Errorf("rsp: non-digit %q in ICCID %q", c, iccid)
		}
	}
	return nil
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
