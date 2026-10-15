package service

import (
	"time"

	"rsp42/internal/client/es12"
	"rsp42/internal/store"
)

// ProfileStore is the subset of profile persistence used by the services. It is
// defined by the consumer so the concrete SQLite repository stays a detail.
type ProfileStore interface {
	GetByICCID(iccid string) (*store.Profile, error)
	GetByMatchingID(matchingID string) (*store.Profile, error)
	GetByID(id int64) (*store.Profile, error)
	Update(p *store.Profile) error
	Delete(iccid string) error
}

// ProfileCreator creates profiles, looks them up for resend detection, updates
// one in place when a cancelled ICCID is re-issued, and removes one again when a
// later allocation step fails (the ICCID pool claim).
type ProfileCreator interface {
	Create(p *store.Profile) (int64, error)
	GetByICCID(iccid string) (*store.Profile, error)
	Update(p *store.Profile) error
	Delete(iccid string) error
}

// SessionStore persists RSP sessions.
type SessionStore interface {
	Put(s *store.Session) error
	Get(transactionID string) (*store.Session, error)
	Delete(transactionID string) error
	GCExpired(now time.Time) (int64, error)
}

// EventStore persists SM-DS event records.
type EventStore interface {
	GetByKey(eid, eventID, callerOID string) (*store.EventRecord, error)
	Insert(e *store.EventRecord) (int64, error)
	SoftDelete(id int64) (bool, error)
	HardDelete(id int64) error
	ListByEID(eid string) ([]*store.EventRecord, error)
	ListByEIDEventID(eid, eventID string) ([]*store.EventRecord, error)
	ListAll() ([]*store.EventRecord, error)
	GCExpired(now time.Time) (int64, error)
}

// RegistrationStore records SM-DP+ event registrations.
type RegistrationStore interface {
	Insert(eid, eventID, rspServerAddress string, forwarding bool, tenant string) error
	ListActiveByEID(eid string) ([]*store.Registration, error)
	MarkDeleted(id int64) error
}

// NotificationStore persists received notifications.
type NotificationStore interface {
	Insert(n *store.Notification) error
}

// CascadeClient forwards event registration/deletion to a Root SM-DS (ES15).
//
// ES15 is structurally identical to ES12 and targets the Root SM-DS ES12 routes;
// the Alternative SM-DS authenticates with CERT.DS.TLS instead of CERT.DP.TLS,
// and the Root side handles those requests in the ES12 handler, which
// distinguishes the caller role from the mTLS client certificate. There is
// therefore no separate ES15 HTTP package: es12.SMDSCClient is the ES15 client
// and api/es12 is the root-side handler.
type CascadeClient interface {
	Register(eid, rspServerAddress, eventID string, forwardingIndicator bool, meta es12.EventMeta) error
	Delete(eid, eventID string, meta es12.EventMeta) error
	// ErrNotFound reports whether an error means "event not found" (ignorable
	// during cascaded deletion).
	IsNotFound(err error) bool
}

// AuditSink records an audit row. It is defined by the consumer so the SQLite
// repository stays a detail; *store.AuditRepo satisfies it.
type AuditSink interface {
	Insert(e *store.AuditEntry) error
}
