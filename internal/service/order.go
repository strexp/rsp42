// Package service implements the business logic shared by the HTTP handlers.
package service

import (
	"fmt"
	"time"

	"rsp42/internal/store"
)

// TransitionError describes an illegal profile state transition.
type TransitionError struct {
	From, To store.ProfileState
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("service: illegal profile transition %s -> %s", e.From, e.To)
}

// allowedTransitions encodes SGP.22 §3.1.6 Table 6b (plus transitions needed by
// CancelOrder, which may return any active/Error state to Available/Unavailable).
var allowedTransitions = map[store.ProfileState]map[store.ProfileState]bool{
	store.StateAvailable: {
		store.StateAllocated: true, store.StateLinked: true, store.StateUnavailable: true,
	},
	store.StateAllocated: {
		store.StateConfirmed: true, store.StateReleased: true, store.StateAvailable: true, store.StateUnavailable: true,
	},
	store.StateLinked: {
		store.StateConfirmed: true, store.StateReleased: true, store.StateAvailable: true, store.StateUnavailable: true,
	},
	store.StateConfirmed: {
		store.StateReleased: true, store.StateAvailable: true, store.StateUnavailable: true,
	},
	store.StateReleased: {
		store.StateDownloaded: true, store.StateAvailable: true, store.StateUnavailable: true, store.StateError: true,
	},
	store.StateDownloaded: {
		store.StateInstalled: true, store.StateError: true, store.StateAvailable: true, store.StateUnavailable: true,
		store.StateDownloaded: true,
	},
	store.StateInstalled: {
		store.StateAvailable: true, store.StateUnavailable: true,
	},
	store.StateError: {
		store.StateAvailable: true, store.StateUnavailable: true,
	},
	store.StateUnavailable: {},
}

// CanTransition reports whether a transition is permitted.
func CanTransition(from, to store.ProfileState) bool {
	if from == to {
		return true // idempotent no-op
	}
	return allowedTransitions[from][to]
}

// AssertTransition returns an error if the transition is not permitted.
func AssertTransition(from, to store.ProfileState) error {
	if !CanTransition(from, to) {
		return &TransitionError{From: from, To: to}
	}
	return nil
}

// ICCIDRecycler returns pooled ICCIDs to their pool when a profile is cancelled
// or deleted.
type ICCIDRecycler interface {
	SetState(iccid, state, note string) error
}

// OrderService drives the profile lifecycle.
type OrderService struct {
	Profiles ProfileStore
	// Pool, when set, receives ICCIDs freed by Cancel/Delete.
	Pool ICCIDRecycler
}

// NewOrderService builds an OrderService.
func NewOrderService(repo ProfileStore) *OrderService { return &OrderService{Profiles: repo} }

// Transition loads the profile, checks the transition and persists the result.
//
// mutate runs on every call, including a protocol resend where the profile
// already holds the target state (CanTransition treats from == to as a legal
// no-op). It receives whether the state actually moved, so that an attribute
// update needed on a resend (the confirmation flag, the failure reason) is
// applied while a non-idempotent counter is only advanced by a real transition.
func (s *OrderService) Transition(iccid string, to store.ProfileState, mutate func(p *store.Profile, stateChanged bool)) (*store.Profile, error) {
	p, err := s.Profiles.GetByICCID(iccid)
	if err != nil {
		return nil, err
	}
	if err := AssertTransition(p.State, to); err != nil {
		return nil, err
	}
	stateChanged := p.State != to
	p.State = to
	if mutate != nil {
		mutate(p, stateChanged)
	}
	// InstalledAt records the first installation; a duplicate notification must
	// not move it forward.
	if to == store.StateInstalled && p.InstalledAt == nil {
		now := time.Now().UTC()
		p.InstalledAt = &now
	}
	if err := s.Profiles.Update(p); err != nil {
		return nil, err
	}
	return p, nil
}

// Allocate moves Available -> Allocated.
func (s *OrderService) Allocate(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateAllocated, nil)
}

// Link moves Available -> Linked.
func (s *OrderService) Link(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateLinked, nil)
}

// Confirm moves Allocated/Linked -> Confirmed or Released. A resend refreshes
// the release flag even when the state does not move.
func (s *OrderService) Confirm(iccid string, release bool) (*store.Profile, error) {
	to := store.StateConfirmed
	if release {
		to = store.StateReleased
	}
	return s.Transition(iccid, to, func(p *store.Profile, _ bool) { p.ReleaseFlag = release })
}

// Release moves Confirmed -> Released.
func (s *OrderService) Release(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateReleased, nil)
}

// MarkDownloaded moves Released -> Downloaded. The download attempt counter is
// only advanced by a real transition: the counter itself is owned by
// CMAE.registerDownloadAttempt (SGP.22 §3.1.3 step 3).
func (s *OrderService) MarkDownloaded(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateDownloaded, func(p *store.Profile, stateChanged bool) {
		if stateChanged {
			p.DownloadAttempts++
		}
	})
}

// MarkInstalled moves Downloaded -> Installed. InstalledAt is only set on the
// first installation.
func (s *OrderService) MarkInstalled(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateInstalled, nil)
}

// MarkError moves Downloaded/Released -> Error. A resend (including one for an
// already-failed profile) records the latest reason.
func (s *OrderService) MarkError(iccid, reason string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateError, func(p *store.Profile, _ bool) { p.ErrorReason = reason })
}

// Cancel moves any active (or Error) state to Available or Unavailable. The
// ICCID is returned to the pool (Available) or parked as blocked (Unavailable).
func (s *OrderService) Cancel(iccid string, unavailable bool) (*store.Profile, error) {
	to := store.StateAvailable
	if unavailable {
		to = store.StateUnavailable
	}
	p, err := s.Transition(iccid, to, nil)
	if err != nil {
		return nil, err
	}
	s.recycle(p.ICCID, unavailable)
	return p, nil
}

// Delete removes a profile and returns its ICCID to the pool.
func (s *OrderService) Delete(iccid string) error {
	if err := s.Profiles.Delete(iccid); err != nil {
		return err
	}
	s.recycle(iccid, false)
	return nil
}

// recycle returns a freed ICCID to its pool. ICCIDs that never came from a pool
// are silently ignored.
func (s *OrderService) recycle(iccid string, unavailable bool) {
	if s.Pool == nil {
		return
	}
	state := "available"
	if unavailable {
		state = "blocked"
	}
	_ = s.Pool.SetState(iccid, state, "")
}
