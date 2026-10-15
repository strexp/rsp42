package service

import (
	"log/slog"

	"rsp42/internal/store"
)

// Registrar registers and deletes SM-DS events on behalf of the SM-DP+
// (SGP.22 §3.6.1 / §3.6.3) and records them for later deletion.
type Registrar struct {
	Repo        RegistrationStore
	Client      *SMDSCClient
	SMDPAddress string
	Forwarding  bool
	Log         *slog.Logger
}

// Register generates an event for the EID and registers it at the SM-DS.
// eventID is normally the profile's matchingId.
//
// Registering an event that is already active for the EID is a no-op: a
// ConfirmOrder resend must not be answered by the SM-DS with "EventID already in
// use" and counted as a registration failure (Table 27's resend NOTE expects a
// resend to take no other action).
func (r *Registrar) Register(eid, eventID, smdsAddress string, meta EventMeta) error {
	if r.Client == nil {
		return nil
	}
	if regs, err := r.Repo.ListActiveByEID(eid); err == nil {
		for _, g := range regs {
			if g.EventID == eventID {
				return nil
			}
		}
	}
	if err := r.Client.Register(eid, r.SMDPAddress, eventID, r.Forwarding, meta); err != nil {
		return err
	}
	return r.Repo.Insert(eid, eventID, smdsAddress, r.Forwarding, meta.Tenant)
}

// DeleteForEID deletes every active registration for the EID at the SM-DS.
func (r *Registrar) DeleteForEID(eid string, meta EventMeta) error {
	return r.deleteMatching(eid, meta, nil)
}

// DeleteEvent deletes the registration held under one event id (normally the
// MatchingID it was registered for) at the SM-DS. It is a no-op when nothing is
// registered under that id. Callers use it when a Profile's MatchingID changes:
// the registration is keyed by the MatchingID, so the previous one no longer
// matches the order (SGP.22 §3.6).
func (r *Registrar) DeleteEvent(eid, eventID string, meta EventMeta) error {
	if eventID == "" {
		return nil
	}
	return r.deleteMatching(eid, meta, func(g *store.Registration) bool { return g.EventID == eventID })
}

// deleteMatching removes the active registrations selected by keep (all of them
// when keep is nil).
func (r *Registrar) deleteMatching(eid string, meta EventMeta, keep func(*store.Registration) bool) error {
	if r.Client == nil {
		return nil
	}
	regs, err := r.Repo.ListActiveByEID(eid)
	if err != nil {
		return err
	}
	for _, g := range regs {
		if keep != nil && !keep(g) {
			continue
		}
		// A not-found answer means the SM-DS already dropped the event; the
		// local row is still marked so it stops being retried.
		if err := r.Client.Delete(eid, g.EventID, meta); err != nil && !r.Client.IsNotFound(err) {
			return err
		}
		_ = r.Repo.MarkDeleted(g.ID)
	}
	return nil
}
