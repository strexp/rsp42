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

// OrderService drives the profile lifecycle.
type OrderService struct {
	Profiles ProfileStore
}

// NewOrderService builds an OrderService.
func NewOrderService(repo ProfileStore) *OrderService { return &OrderService{Profiles: repo} }

// Transition loads the profile, checks the transition and persists it.
func (s *OrderService) Transition(iccid string, to store.ProfileState, mutate func(*store.Profile)) (*store.Profile, error) {
	p, err := s.Profiles.GetByICCID(iccid)
	if err != nil {
		return nil, err
	}
	if err := AssertTransition(p.State, to); err != nil {
		return nil, err
	}
	if p.State == to {
		return p, nil // idempotent
	}
	p.State = to
	if mutate != nil {
		mutate(p)
	}
	if to == store.StateInstalled {
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

// Confirm moves Allocated/Linked -> Confirmed or Released.
func (s *OrderService) Confirm(iccid string, release bool) (*store.Profile, error) {
	to := store.StateConfirmed
	if release {
		to = store.StateReleased
	}
	return s.Transition(iccid, to, func(p *store.Profile) { p.ReleaseFlag = release })
}

// Release moves Confirmed -> Released.
func (s *OrderService) Release(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateReleased, nil)
}

// MarkDownloaded moves Released -> Downloaded (or stays Downloaded).
func (s *OrderService) MarkDownloaded(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateDownloaded, func(p *store.Profile) { p.DownloadAttempts++ })
}

// MarkInstalled moves Downloaded -> Installed.
func (s *OrderService) MarkInstalled(iccid string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateInstalled, nil)
}

// MarkError moves Downloaded -> Error.
func (s *OrderService) MarkError(iccid, reason string) (*store.Profile, error) {
	return s.Transition(iccid, store.StateError, func(p *store.Profile) { p.ErrorReason = reason })
}

// Cancel moves any active (or Error) state to Available or Unavailable.
func (s *OrderService) Cancel(iccid string, unavailable bool) (*store.Profile, error) {
	to := store.StateAvailable
	if unavailable {
		to = store.StateUnavailable
	}
	return s.Transition(iccid, to, nil)
}
