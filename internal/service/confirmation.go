package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// hexLower decodes a hex-encoded string (either case). Transaction IDs reach
// the service from an HTTP request body, so a malformed value is reported as an
// error rather than a panic.
func hexLower(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("service: %q is not a hex string: %w", s, err)
	}
	return b, nil
}

// confirmationHash computes hashCc = SHA256(SHA256(CC) || transactionId)
// (SGP.22 §2.2), where ccHash is the stored SHA256(CC).
func confirmationHash(ccHash, transactionID []byte) []byte {
	h := sha256.New()
	h.Write(ccHash)
	h.Write(transactionID)
	return h.Sum(nil)
}
