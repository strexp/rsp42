package service

import (
	"time"

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

// ProfileCreator creates profiles and looks them up for resend detection.
type ProfileCreator interface {
	Create(p *store.Profile) (int64, error)
	GetByICCID(iccid string) (*store.Profile, error)
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
