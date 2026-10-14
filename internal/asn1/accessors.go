package asn1

import "fmt"

// Bytes returns the primitive content.
func (t TLV) Bytes() []byte { return t.Value }

// Int decodes a signed INTEGER.
func (t TLV) Int() (int64, error) {
	if len(t.Value) == 0 || len(t.Value) > 8 {
		return 0, fmt.Errorf("asn1: bad INTEGER length %d", len(t.Value))
	}
	v := int64(0)
	if t.Value[0]&0x80 != 0 {
		v = -1
	}
	for _, b := range t.Value {
		v = v<<8 | int64(b)
	}
	return v, nil
}

// Bool decodes a BOOLEAN.
func (t TLV) Bool() (bool, error) {
	if len(t.Value) != 1 {
		return false, fmt.Errorf("asn1: bad BOOLEAN length %d", len(t.Value))
	}
	return t.Value[0] != 0, nil
}

// BitString returns the unused-bit count and the bit string content.
func (t TLV) BitString() (uint8, []byte, error) {
	if len(t.Value) == 0 {
		return 0, nil, fmt.Errorf("asn1: empty BIT STRING")
	}
	return t.Value[0], t.Value[1:], nil
}

// BitSet reports whether bit i (0 = most significant of the first content
// byte) is set in a BIT STRING, ignoring the unused-bits prefix.
func (t TLV) BitSet(i int) (bool, error) {
	_, bits, err := t.BitString()
	if err != nil {
		return false, err
	}
	byteIdx := i / 8
	if byteIdx >= len(bits) {
		return false, nil
	}
	return bits[byteIdx]&(0x80>>(uint(i)%8)) != 0, nil
}
