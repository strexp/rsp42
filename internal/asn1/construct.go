package asn1

import (
	"encoding/binary"
	"math/big"

	"github.com/euicc-go/bertlv"
)

// Universal tag constants.
var (
	TagBoolean    = encodeTag(0, 0, 1)
	TagInteger    = encodeTag(0, 0, 2)
	TagBitString  = encodeTag(0, 0, 3)
	TagOctetStr   = encodeTag(0, 0, 4)
	TagNull       = encodeTag(0, 0, 5)
	TagOID        = encodeTag(0, 0, 6)
	TagEnumerated = encodeTag(0, 0, 10)
	TagUTF8String = encodeTag(0, 0, 12)
	TagSequence   = encodeTag(0, 1, 16)
)

// Tag is re-exported for callers that build tags directly.
type Tag = bertlv.Tag

// Builder is the mutable BER-TLV value produced by the construction helpers in
// this file (New, Seq, Prim, Octet, ...) and serialized by Marshal. It is an
// alias for the low-level bertlv type, exported so that callers outside this
// package never have to import github.com/euicc-go/bertlv themselves. It is a
// different type from Node, which is the editable tree used for SAIP
// ProfileElements.
type Builder = bertlv.TLV

// BER tag classes and forms.
const (
	classUniversal   = 0
	classApplication = 1
	classContext     = 2
	formPrimitive    = 0
	formConstructed  = 1
)

// encodeTag encodes a BER identifier octet sequence, using the minimal
// high-tag-number form. It intentionally does not use bertlv.NewTag, which
// emits a non-minimal encoding for tag values whose bit length is a multiple
// of seven (e.g. 0x49).
func encodeTag(class, form byte, value uint64) []byte {
	first := class<<6 | form<<5
	if value < 0x1f {
		return []byte{first | byte(value)}
	}
	first |= 0x1f
	var body []byte
	body = append(body, byte(value&0x7f))
	for value >>= 7; value > 0; value >>= 7 {
		body = append([]byte{byte(value&0x7f) | 0x80}, body...)
	}
	return append([]byte{first}, body...)
}

// App returns an APPLICATION-class tag.
func App(n uint64, constructed bool) bertlv.Tag {
	if constructed {
		return encodeTag(classApplication, formConstructed, n)
	}
	return encodeTag(classApplication, formPrimitive, n)
}

// Ctx returns a CONTEXT-SPECIFIC-class tag.
func Ctx(n uint64, constructed bool) bertlv.Tag {
	if constructed {
		return encodeTag(classContext, formConstructed, n)
	}
	return encodeTag(classContext, formPrimitive, n)
}

// Seq builds a universal SEQUENCE.
func Seq(children ...*Builder) *Builder { return bertlv.NewChildren(TagSequence, children...) }

// New builds a constructed TLV with an arbitrary tag.
func New(tag bertlv.Tag, children ...*Builder) *Builder {
	return bertlv.NewChildren(tag, children...)
}

// Prim builds a primitive TLV with an arbitrary tag.
func Prim(tag bertlv.Tag, value []byte) *Builder { return bertlv.NewValue(tag, value) }

// Octet builds an OCTET STRING.
func Octet(b []byte) *Builder { return bertlv.NewValue(TagOctetStr, b) }

// Null builds a NULL.
func Null() *Builder { return bertlv.NewValue(TagNull, nil) }

// Bool builds a BOOLEAN.
func Bool(v bool) *Builder {
	if v {
		return bertlv.NewValue(TagBoolean, []byte{0xff})
	}
	return bertlv.NewValue(TagBoolean, []byte{0x00})
}

// UTF8 builds a UTF8String.
func UTF8(s string) *Builder { return bertlv.NewValue(TagUTF8String, []byte(s)) }

// Int builds an INTEGER from the minimal two's-complement encoding.
func Int(v int64) *Builder { return bertlv.NewValue(TagInteger, encodeInt(v)) }

// IntBytes returns the minimal two's-complement content of an INTEGER value.
func IntBytes(v int64) []byte { return encodeInt(v) }

// Enumerated builds an ENUMERATED.
func Enumerated(v int64) *Builder { return bertlv.NewValue(TagEnumerated, encodeInt(v)) }

// BitString builds a BIT STRING. bits is the value with trailing bits already
// zeroed; unused is the number of unused trailing bits (0..7).
func BitString(unused uint8, bits []byte) *Builder {
	value := append([]byte{unused}, bits...)
	return bertlv.NewValue(TagBitString, value)
}

// OID builds an OBJECT IDENTIFIER from its dotted string form.
func OID(oid string) *Builder { return bertlv.NewValue(TagOID, EncodeOID(oid)) }

// Sequence wraps children in a UNIVERSAL SEQUENCE and returns the encoded bytes.
func Marshal(t *Builder) []byte {
	b, err := t.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func encodeInt(v int64) []byte {
	if v >= 0 {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(v))
		i := 0
		for i < 8 && buf[i] == 0 {
			i++
		}
		b := buf[i:]
		if len(b) == 0 {
			b = []byte{0}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return b
	}
	bi := big.NewInt(v)
	for size := 1; size <= 8; size++ {
		min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(size*8-1)))
		if bi.Cmp(min) >= 0 {
			mod := new(big.Int).Lsh(big.NewInt(1), uint(size*8))
			enc := new(big.Int).Add(bi, mod)
			b := enc.Bytes()
			padded := make([]byte, size)
			copy(padded[size-len(b):], b)
			return padded
		}
	}
	panic("asn1: integer out of range")
}
