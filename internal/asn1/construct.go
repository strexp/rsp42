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
	TagUTF8String = encodeTag(0, 0, 12)
	TagSequence   = encodeTag(0, 1, 16)
)

// Tag is a BER identifier octet sequence (one or more bytes; the high-tag-number
// form for values >= 31). It is a plain byte slice so callers can use App/Ctx or
// write a tag literally, and so this package's API names no third-party type.
type Tag = []byte

// Builder is the BER-TLV value produced by the construction helpers in this file
// (New, Seq, Prim, Octet, ...) and serialized by Marshal. It wraps the
// low-level TLV type so that no caller outside this package has to name it, and
// so the underlying library can be replaced without changing this API. Node is
// the editable tree used for SAIP ProfileElements.
type Builder struct{ tlv *bertlv.TLV }

func wrap(t *bertlv.TLV) *Builder { return &Builder{tlv: t} }

// unwrap converts a Builder list to the underlying library's children. The
// values are created by this package, so a nil entry is a programming error.
func unwrap(children []*Builder) []*bertlv.TLV {
	out := make([]*bertlv.TLV, len(children))
	for i, c := range children {
		out[i] = c.tlv
	}
	return out
}

// MarshalBinary returns the DER/BER encoding of the builder.
func (b *Builder) MarshalBinary() ([]byte, error) { return b.tlv.MarshalBinary() }

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
func App(n uint64, constructed bool) Tag {
	if constructed {
		return encodeTag(classApplication, formConstructed, n)
	}
	return encodeTag(classApplication, formPrimitive, n)
}

// Ctx returns a CONTEXT-SPECIFIC-class tag.
func Ctx(n uint64, constructed bool) Tag {
	if constructed {
		return encodeTag(classContext, formConstructed, n)
	}
	return encodeTag(classContext, formPrimitive, n)
}

// Seq builds a universal SEQUENCE.
func Seq(children ...*Builder) *Builder {
	return wrap(bertlv.NewChildren(TagSequence, unwrap(children)...))
}

// New builds a constructed TLV with an arbitrary tag.
func New(tag Tag, children ...*Builder) *Builder {
	return wrap(bertlv.NewChildren(bertlv.Tag(tag), unwrap(children)...))
}

// Prim builds a primitive TLV with an arbitrary tag.
func Prim(tag Tag, value []byte) *Builder { return wrap(bertlv.NewValue(bertlv.Tag(tag), value)) }

// Octet builds an OCTET STRING.
func Octet(b []byte) *Builder { return wrap(bertlv.NewValue(TagOctetStr, b)) }

// Bool builds a BOOLEAN.
func Bool(v bool) *Builder {
	if v {
		return wrap(bertlv.NewValue(TagBoolean, []byte{0xff}))
	}
	return wrap(bertlv.NewValue(TagBoolean, []byte{0x00}))
}

// UTF8 builds a UTF8String.
func UTF8(s string) *Builder { return wrap(bertlv.NewValue(TagUTF8String, []byte(s))) }

// Int builds an INTEGER from the minimal two's-complement encoding.
func Int(v int64) *Builder { return wrap(bertlv.NewValue(TagInteger, encodeInt(v))) }

// IntBytes returns the minimal two's-complement content of an INTEGER value.
func IntBytes(v int64) []byte { return encodeInt(v) }

// BitString builds a BIT STRING. bits is the value with trailing bits already
// zeroed; unused is the number of unused trailing bits (0..7).
func BitString(unused uint8, bits []byte) *Builder {
	value := append([]byte{unused}, bits...)
	return wrap(bertlv.NewValue(TagBitString, value))
}

// Marshal encodes a Builder and returns the bytes. It panics when the value
// cannot be encoded, which includes two limits inherited from bertlv: a content
// length above 65535 bytes, and a constructed tag carrying a raw value. Callers
// that need large content or a constructed element with pre-encoded content must
// write the tag/length themselves (see rsp.tlvBytes, which does exactly that).
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
