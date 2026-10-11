package asn1

import (
	"fmt"
	"strconv"
	"strings"
)

// EncodeOID encodes a dotted OBJECT IDENTIFIER string into DER content bytes.
func EncodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		panic("asn1: OID needs at least two components: " + oid)
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			panic("asn1: invalid OID component " + p)
		}
		nums[i] = n
	}
	out := encodeOIDComponent(nums[0]*40 + nums[1])
	for _, n := range nums[2:] {
		out = append(out, encodeOIDComponent(n)...)
	}
	return out
}

func encodeOIDComponent(n uint64) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n & 0x7f)}, tmp...)
		n >>= 7
	}
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] |= 0x80
	}
	return tmp
}

// DecodeOID decodes DER OID content bytes into dotted string form.
func DecodeOID(b []byte) (string, error) {
	if len(b) == 0 {
		return "", fmt.Errorf("asn1: empty OID")
	}
	var comps []uint64
	var cur uint64
	for i, c := range b {
		if cur > (1 << 57) {
			return "", fmt.Errorf("asn1: OID component too large")
		}
		cur = cur<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			comps = append(comps, cur)
			cur = 0
		} else if i == len(b)-1 {
			return "", fmt.Errorf("asn1: truncated OID")
		}
	}
	if len(comps) == 0 {
		return "", fmt.Errorf("asn1: empty OID")
	}
	first := comps[0]
	var x, y uint64
	switch {
	case first < 40:
		x, y = 0, first
	case first < 80:
		x, y = 1, first-40
	default:
		x, y = 2, first-80
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d.%d", x, y)
	for _, c := range comps[1:] {
		fmt.Fprintf(&sb, ".%d", c)
	}
	return sb.String(), nil
}
