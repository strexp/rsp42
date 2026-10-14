package service

import (
	"encoding/hex"
	"testing"
)

// mustHexLower decodes a hex string in tests, where a malformed literal is a
// failing test rather than a runtime error. Production code uses hexLower.
func mustHexLower(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("test literal %q is not hex: %v", s, err)
	}
	return b
}
