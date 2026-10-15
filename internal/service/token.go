package service

import (
	"crypto/rand"
	"rsp42/internal/hexutil"
)

func randomToken() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hexutil.Upper(b)
}

// NewEventID returns a fresh "EVT-<token>" event identifier.
func NewEventID() string {
	return "EVT-" + randomToken()
}
