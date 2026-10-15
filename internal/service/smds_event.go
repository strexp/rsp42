package service

import (
	"errors"
	"fmt"
	"time"

	"rsp42/internal/client/es12"
	"rsp42/internal/store"
)

// EventService implements the SM-DS event store semantics (SGP.22 §3.6).
type EventService struct {
	Repo       EventStore
	Role       string // "root" | "alternative"
	OwnAddress string
	Cascade    CascadeClient
	EventTTL   time.Duration
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
func (s *EventService) Register(eid, rspServerAddress, eventID string, forwardingIndicator bool, callerOID string, meta es12.EventMeta) error {
	// A lookup error that is not "missing" is a storage failure: it must be
	// reported, not mistaken for "the EventID is free".
	if _, err := s.Repo.GetByKey(eid, eventID, callerOID); err == nil {
		return ErrEventIDInUse
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
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
		rootEventID := NewEventID()
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
		// Only "no such event" maps to ErrEventNotFound; a storage failure must
		// stay distinguishable so the caller can answer with a server error.
		if errors.Is(err, store.ErrNotFound) {
			return ErrEventNotFound
		}
		return err
	}
	if rec.DeletedAt != nil {
		return ErrEventNotFound
	}
	if rec.Cascaded {
		if s.Cascade == nil {
			return fmt.Errorf("event: cascading to root SM-DS is not configured")
		}
		if err := s.Cascade.Delete(eid, rec.RootEventID, es12.EventMeta{Tenant: rec.TenantID}); err != nil {
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
