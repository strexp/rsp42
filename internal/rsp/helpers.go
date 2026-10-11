package rsp

import "rsp42/internal/asn1"

func encodeInt(v int64) []byte { return asn1.IntBytes(v) }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Small helpers -------------------------------------------------------------

func firstChild(t asn1.TLV) (asn1.TLV, bool) { return t.First() }

func hexTag(tag []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(tag)*2)
	for _, b := range tag {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}
