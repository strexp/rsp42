// Package testutil holds helpers shared by the test suites of several packages.
//
// It must stay dependency-free (no rsp42 imports) so any package can use it, and
// it must never be imported by non-test code: it is not linked into the binary
// as long as only _test.go files reference it.
package testutil

import (
	"encoding/hex"
	"testing"
)

// MustHex decodes a hex string, failing the test on a malformed literal.
func MustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("testutil: %q is not hex: %v", s, err)
	}
	return b
}

// Concat returns the concatenation of the given byte slices.
func Concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// TLV builds a tag + definite-length + content element, matching the BER
// encoding used on the wire. It lets a test assert on individual TLVs without
// pulling the production encoders into the expectation.
func TLV(tag, content []byte) []byte {
	return Concat(tag, EncodeLength(len(content)), content)
}

// HexTag renders a tag as lowercase hex.
func HexTag(tag []byte) string { return hex.EncodeToString(tag) }
