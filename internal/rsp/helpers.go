package rsp

import "rsp42/internal/asn1"

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Small helpers -------------------------------------------------------------

func firstChild(t asn1.TLV) (asn1.TLV, bool) { return t.First() }
