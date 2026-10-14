package service

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"rsp42/internal/store"
)

// CascadeClient forwards event registration/deletion to a Root SM-DS (ES15).
type CascadeClient interface {
	Register(eid, rspServerAddress, eventID string, forwardingIndicator bool, meta EventMeta) error
	Delete(eid, eventID string, meta EventMeta) error
	// ErrNotFound reports whether an error means "event not found" (ignorable
	// during cascaded deletion).
	IsNotFound(err error) bool
}

// EventService implements the SM-DS event store semantics (SGP.22 §3.6).
type EventService struct {
	Repo       EventStore
	Role       string // "root" | "alternative"
	OwnAddress string
	Cascade    CascadeClient
	EventTTL   time.Duration
	Log        *slog.Logger
}

// NewEventService builds an EventService.
func NewEventService(repo EventStore, role, ownAddress string, ttl time.Duration) *EventService {
	return &EventService{Repo: repo, Role: role, OwnAddress: ownAddress, EventTTL: ttl}
}

// ErrEventIDInUse is returned when an EventID is already in use by the caller.
var ErrEventIDInUse = errors.New("event id already in use")

// ErrEventNotFound is returned when no matching event record exists.
var ErrEventNotFound = errors.New("event not found")

// Register stores an event. For an Alternative SM-DS with forwardingIndicator
// set, it cascades to the Root SM-DS (generating EventID2) and rolls back the
// local record on failure.
func (s *EventService) Register(eid, rspServerAddress, eventID string, forwardingIndicator bool, callerOID string, meta EventMeta) error {
	if _, err := s.Repo.GetByKey(eid, eventID, callerOID); err == nil {
		return ErrEventIDInUse
	}

	rec := &store.EventRecord{
		EID:                 eid,
		EventID:             eventID,
		RSPServerAddress:    rspServerAddress,
		CallerOID:           callerOID,
		ForwardingIndicator: forwardingIndicator,
		TenantID:            meta.Tenant,
		ICCID:               meta.ICCID,
		MatchingID:          meta.MatchingID,
	}
	if s.EventTTL > 0 {
		t := time.Now().UTC().Add(s.EventTTL)
		rec.ExpiresAt = &t
	}

	// Root SM-DS ignores the forwarding indicator.
	if s.Role == "alternative" && forwardingIndicator {
		rec.Cascaded = true
		rootEventID := newEventID()
		rec.RootEventID = rootEventID
		id, err := s.Repo.Insert(rec)
		if err != nil {
			if errors.Is(err, store.ErrEventIDInUse) {
				return ErrEventIDInUse
			}
			return err
		}
		if s.Cascade == nil {
			_ = s.Repo.HardDelete(id)
			return fmt.Errorf("event: cascading to root SM-DS is not configured")
		}
		if err := s.Cascade.Register(eid, s.OwnAddress, rootEventID, false, meta); err != nil {
			_ = s.Repo.HardDelete(id) // roll back local record
			return err
		}
		return nil
	}

	_, err := s.Repo.Insert(rec)
	if errors.Is(err, store.ErrEventIDInUse) {
		return ErrEventIDInUse
	}
	return err
}

// Delete removes an event owned by callerOID. Cascaded records are first
// deleted at the Root SM-DS (a "not found" there is ignored); other failures
// leave the local record intact.
func (s *EventService) Delete(eid, eventID, callerOID string) error {
	rec, err := s.Repo.GetByKey(eid, eventID, callerOID)
	if err != nil {
		return ErrEventNotFound
	}
	if rec.DeletedAt != nil {
		return ErrEventNotFound
	}
	if rec.Cascaded {
		if s.Cascade == nil {
			return fmt.Errorf("event: cascading to root SM-DS is not configured")
		}
		if err := s.Cascade.Delete(eid, rec.RootEventID, EventMeta{Tenant: rec.TenantID}); err != nil {
			if !s.Cascade.IsNotFound(err) {
				return err
			}
		}
	}
	if _, err := s.Repo.SoftDelete(rec.ID); err != nil {
		return err
	}
	return nil
}

// ListForEID returns the active events for an EID in registration order.
func (s *EventService) ListForEID(eid string) ([]*store.EventRecord, error) {
	return s.Repo.ListByEID(eid)
}

// LookupByEventID returns the active events matching an EID and EventID.
func (s *EventService) LookupByEventID(eid, eventID string) ([]*store.EventRecord, error) {
	return s.Repo.ListByEIDEventID(eid, eventID)
}

func newEventID() string {
	return "EVT-" + randomToken()
}
