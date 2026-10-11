package asn1

import (
	"fmt"
	"math/big"
)

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

// Uint decodes an unsigned INTEGER (rejecting negative values).
func (t TLV) Uint() (uint64, error) {
	if len(t.Value) == 0 {
		return 0, fmt.Errorf("asn1: empty INTEGER")
	}
	if t.Value[0]&0x80 != 0 {
		return 0, fmt.Errorf("asn1: negative INTEGER in unsigned context")
	}
	u := new(big.Int).SetBytes(t.Value)
	if !u.IsUint64() {
		return 0, fmt.Errorf("asn1: INTEGER overflows uint64")
	}
	return u.Uint64(), nil
}

// OID decodes an OBJECT IDENTIFIER.
func (t TLV) OID() (string, error) { return DecodeOID(t.Value) }

// Str returns the content as a string.
func (t TLV) Str() string { return string(t.Value) }

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

// MustTag returns an error when the TLV tag does not match want.
func (t TLV) MustTag(want []byte) error {
	if !bytesEqual(t.Tag, want) {
		return fmt.Errorf("asn1: unexpected tag %X, want %X", t.Tag, want)
	}
	return nil
}
