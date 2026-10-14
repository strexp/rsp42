package store

import "time"

// EventRecord is a row of the SM-DS event store (SGP.22 §3.6).
type EventRecord struct {
	ID                  int64
	EID                 string
	EventID             string
	RSPServerAddress    string
	CallerOID           string
	ForwardingIndicator bool
	Cascaded            bool
	RootEventID         string
	// TenantID/ICCID/MatchingID are rsp42-internal correlation fields (the
	// ES12 body is a closed set, so the tenant travels in a request header).
	TenantID     string
	ICCID        string
	MatchingID   string
	RegisteredAt time.Time
	ExpiresAt    *time.Time
	DeletedAt    *time.Time
}
