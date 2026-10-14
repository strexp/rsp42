package rsp

import "rsp42/internal/asn1"

// Child lookup helpers used by the message decoders: a missing optional field
// yields the zero value (an absent field and an empty one are indistinguishable
// on the wire for the fields these are used for).

func childBytes(t asn1.TLV, tag []byte) []byte {
	c, ok := t.Find(tag)
	if !ok {
		return nil
	}
	return c.Value
}

func childString(t asn1.TLV, tag []byte) string {
	c, ok := t.Find(tag)
	if !ok {
		return ""
	}
	return string(c.Value)
}
