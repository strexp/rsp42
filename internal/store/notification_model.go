package store

import "time"

// Notification is a received notification row.
type Notification struct {
	ID              int64
	EID             string
	SeqNumber       int64
	Operation       string
	ICCID           string
	TransactionID   string
	FinalResultJSON string
	SignatureOK     bool
	ReceivedAt      time.Time
	Processed       bool
}
