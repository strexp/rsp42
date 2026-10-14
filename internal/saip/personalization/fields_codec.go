package personalization

import (
	"encoding/hex"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
)

func hexBytes(s, name string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X"))
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", name, err)
	}
	return b, nil
}

// hexByte decodes a single-byte hex field.
func hexByte(s, name string) ([]byte, error) {
	b, err := hexBytes(s, name)
	if err != nil {
		return nil, err
	}
	if len(b) != 1 {
		return nil, fmt.Errorf("%s must be exactly 1 byte, got %d", name, len(b))
	}
	return b, nil
}

// applyPLMN writes the preferred PLMN list into EF.PLMNwAcT and EF.HPLMNwAcT
// (whichever the template provides).

func ICCIDHeaderBytes(iccid string) ([]byte, error) {
	padded := iccid
	for len(padded) < 20 {
		padded += "F"
	}
	if len(padded) != 20 {
		return nil, fmt.Errorf("personalization: ICCID %q has %d digits", iccid, len(iccid))
	}
	return hex.DecodeString(padded)
}

// ICCIDEFBytes encodes EF.ICCID (3GPP nibble-swapped BCD).
func ICCIDEFBytes(iccid string) ([]byte, error) {
	digits := []byte(iccid)
	if len(digits)%2 != 0 {
		digits = append(digits, 'F')
	}
	out := make([]byte, len(digits)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := digits[2*i], digits[2*i+1]
		if err := checkHex(hi); err != nil {
			return nil, err
		}
		if err := checkHex(lo); err != nil {
			return nil, err
		}
		out[i] = nibble(hi) | nibble(lo)<<4
	}
	// Pad to 10 bytes.
	for len(out) < 10 {
		out = append(out, 0xff)
	}
	return out, nil
}

// EncodeIMSI encodes an IMSI as EF.IMSI content (3GPP TS 31.102).

func EncodeIMSI(imsi string) []byte {
	oe := byte(len(imsi) & 1)
	digits := imsi
	for len(digits) < 15 {
		digits += "F"
	}
	s := fmt.Sprintf("%01x", (oe<<3)|1) + digits
	b := make([]byte, len(s)/2)
	for i := range b {
		b[i] = nibble(s[2*i])<<4 | nibble(s[2*i+1])
	}
	// swap nibbles
	for i := range b {
		b[i] = b[i]>>4 | b[i]<<4
	}
	return append([]byte{byte((len(imsi) + 1 + 1) / 2)}, b...)
}

func setChild(parent *asn1.Node, tag, value []byte) {
	if c := parent.Find(tag); c != nil {
		c.Value = append([]byte(nil), value...)
		return
	}
	parent.AppendChild(asn1.NewPrimitive(tag, value))
}

func nibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func checkHex(c byte) error {
	if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
		return nil
	}
	return fmt.Errorf("personalization: non-hex ICCID digit %q", c)
}
