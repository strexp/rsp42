package asn1

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// EncodeOID encodes a dotted OBJECT IDENTIFIER string into DER content bytes.
//
// It returns an error (never panics) so that an operator-supplied OID cannot
// abort the process. The rules mirror X.690 §8.19: at least two arcs, the
// first arc 0, 1 or 2, and a second arc of 40 or more only when the first arc
// is 2. Every arc must be a non-negative decimal integer that fits in uint64.
func EncodeOID(oid string) ([]byte, error) {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("asn1: OID %q needs at least two components", oid)
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("asn1: OID %q has an empty component", oid)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("asn1: OID %q component %q is not a uint64: %w", oid, p, err)
		}
		nums[i] = n
	}
	if nums[0] > 2 {
		return nil, fmt.Errorf("asn1: OID %q first arc must be 0, 1 or 2, got %d", oid, nums[0])
	}
	if nums[0] < 2 && nums[1] > 39 {
		return nil, fmt.Errorf("asn1: OID %q second arc must be <= 39 when the first arc is %d, got %d", oid, nums[0], nums[1])
	}
	if nums[0] == 2 && nums[1] > math.MaxUint64-80 {
		return nil, fmt.Errorf("asn1: OID %q first two arcs overflow", oid)
	}
	out := encodeOIDComponent(nums[0]*40 + nums[1])
	for _, n := range nums[2:] {
		out = append(out, encodeOIDComponent(n)...)
	}
	return out, nil
}

// MustEncodeOID is EncodeOID for compile-time-constant OID literals. It panics
// on an invalid literal, which can only be a programming error; dynamic input
// must use EncodeOID.
func MustEncodeOID(oid string) []byte {
	b, err := EncodeOID(oid)
	if err != nil {
		panic(err)
	}
	return b
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
