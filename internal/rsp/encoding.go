package rsp

import (
	"encoding/hex"
	"fmt"
)

// EIDBytes converts a 32-digit EID string into its 16-byte binary form (the
// digits are taken in order, two per byte).
func EIDBytes(eid string) ([]byte, error) {
	if len(eid) != 32 {
		return nil, fmt.Errorf("rsp: invalid EID %q", eid)
	}
	for i := 0; i < len(eid); i++ {
		if eid[i] < '0' || eid[i] > '9' {
			return nil, fmt.Errorf("rsp: invalid EID %q", eid)
		}
	}
	return hex.DecodeString(eid)
}
