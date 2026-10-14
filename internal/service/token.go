package service

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

func randomToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}

// NewEventID returns a fresh "EVT-<token>" event identifier.
func NewEventID() string {
	return "EVT-" + randomToken()
}
