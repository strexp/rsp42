package asn1

import (
	"bytes"
	"errors"
	"fmt"
)

// TLV is a parsed BER-TLV element that preserves the exact wire bytes. It is
// used wherever SGP.22 requires signing or verifying an exact byte slice (the
// "raw" representation), which re-encoding cannot guarantee.
type TLV struct {
	Raw         []byte
	Tag         []byte
	Value       []byte // content bytes (primitive value or concatenated children)
	Constructed bool
}

// ErrTruncated is returned when the buffer ends before a TLV is complete.
var ErrTruncated = errors.New("asn1: truncated TLV")

// ReadTLV parses a single BER-TLV element from the front of b. It does not
// interpret the content beyond determining its length, so it can be used on
// arbitrary constructed tags (including the SGP.22 two-byte application and
// context tags).
func ReadTLV(b []byte) (TLV, []byte, error) {
	var t TLV
	tag, n, err := readTag(b)
	if err != nil {
		return t, nil, err
	}
	length, ln, err := readLength(b[n:])
	if err != nil {
		return t, nil, err
	}
	header := n + ln
	if len(b) < header+length {
		return t, nil, fmt.Errorf("%w: tag %X wants %d bytes, have %d", ErrTruncated, tag, length, len(b)-header)
	}
	t.Tag = tag
	t.Value = b[header : header+length]
	t.Raw = b[:header+length]
	t.Constructed = tag[0]&0x20 != 0
	return t, b[header+length:], nil
}

// ReadTLVs parses every TLV in b (used for the UPP, which is a bare
// concatenation of ProfileElements with no outer SEQUENCE).
func ReadTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	rest := b
	for len(rest) > 0 {
		t, r, err := ReadTLV(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		rest = r
	}
	return out, nil
}

// Children parses the content of a constructed TLV into child TLVs.
func (t TLV) Children() ([]TLV, error) {
	if !t.Constructed {
		return nil, fmt.Errorf("asn1: tag %X is not constructed", t.Tag)
	}
	return ReadTLVs(t.Value)
}

// Find returns the first child whose tag matches, comparing full tag bytes.
//
// A constructed value whose content cannot be parsed is reported as "absent",
// exactly like a missing tag. Callers that must tell the two apart use FindErr
// (or Children directly). Every decoder in this repository treats a malformed
// element as a failure further down the pipeline (a signature check, a required
// field check), so the distinction is only needed where a precise diagnostic
// matters.
func (t TLV) Find(tag []byte) (TLV, bool) {
	kids, err := t.Children()
	if err != nil {
		return TLV{}, false
	}
	for _, k := range kids {
		if bytes.Equal(k.Tag, tag) {
			return k, true
		}
	}
	return TLV{}, false
}

// FindErr is Find with the child-parse error preserved: ok is false and err is
// non-nil when the content is malformed, which Find cannot express.
func (t TLV) FindErr(tag []byte) (child TLV, ok bool, err error) {
	kids, err := t.Children()
	if err != nil {
		return TLV{}, false, err
	}
	for _, k := range kids {
		if bytes.Equal(k.Tag, tag) {
			return k, true, nil
		}
	}
	return TLV{}, false, nil
}

// FindAll returns every child whose tag matches. Like Find it reports an
// unparsable constructed value as an empty result.
func (t TLV) FindAll(tag []byte) []TLV {
	kids, err := t.Children()
	if err != nil {
		return nil
	}
	var out []TLV
	for _, k := range kids {
		if bytes.Equal(k.Tag, tag) {
			out = append(out, k)
		}
	}
	return out
}

// First returns the first child, or false when there are none. Like Find it
// reports an unparsable constructed value as "no child".
func (t TLV) First() (TLV, bool) {
	kids, err := t.Children()
	if err != nil || len(kids) == 0 {
		return TLV{}, false
	}
	return kids[0], true
}

// ReadHeader parses a BER tag and length from b and returns the tag and the
// number of header bytes. Unlike ReadTLV it does not require that the declared
// length is actually present; this is used for BSP segments whose MAC has
// already been stripped (the length field still counts the MAC).
func ReadHeader(b []byte) (tag []byte, headerLen int, err error) {
	tag, n, err := readTag(b)
	if err != nil {
		return nil, 0, err
	}
	_, ln, err := readLength(b[n:])
	if err != nil {
		return nil, 0, err
	}
	return tag, n + ln, nil
}

// readTag reads a BER tag (one or more bytes) from b.
func readTag(b []byte) ([]byte, int, error) {
	if len(b) < 1 {
		return nil, 0, ErrTruncated
	}
	if b[0]&0x1f != 0x1f {
		return b[:1], 1, nil
	}
	for i := 1; i < len(b); i++ {
		if b[i]&0x80 == 0 {
			return b[:i+1], i + 1, nil
		}
	}
	return nil, 0, ErrTruncated
}

// readLength reads a BER length. Only the definite form is supported, which is
// all SGP.22 uses.
func readLength(b []byte) (int, int, error) {
	if len(b) < 1 {
		return 0, 0, ErrTruncated
	}
	first := b[0]
	if first&0x80 == 0 {
		return int(first), 1, nil
	}
	n := int(first & 0x7f)
	if n == 0 {
		return 0, 0, errors.New("asn1: indefinite length not supported")
	}
	if n > 4 {
		return 0, 0, fmt.Errorf("asn1: unsupported length field of %d bytes", n)
	}
	if len(b) < 1+n {
		return 0, 0, ErrTruncated
	}
	length := 0
	for i := 1; i <= n; i++ {
		length = length<<8 | int(b[i])
	}
	return length, 1 + n, nil
}

// EncodeLength returns the definite-length encoding of n.
func EncodeLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	case n < 0x1000000:
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}
