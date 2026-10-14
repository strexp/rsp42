package service

import (
	"log/slog"
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
func (r *Registrar) Register(eid, eventID, smdsAddress string, meta EventMeta) error {
	if r.Client == nil {
		return nil
	}
	if err := r.Client.Register(eid, r.SMDPAddress, eventID, r.Forwarding, meta); err != nil {
		return err
	}
	return r.Repo.Insert(eid, eventID, smdsAddress, r.Forwarding, meta.Tenant)
}

// DeleteForEID deletes every active registration for the EID at the SM-DS.
func (r *Registrar) DeleteForEID(eid string, meta EventMeta) error {
	if r.Client == nil {
		return nil
	}
	regs, err := r.Repo.ListActiveByEID(eid)
	if err != nil {
		return err
	}
	for _, g := range regs {
		if err := r.Client.Delete(eid, g.EventID, meta); err != nil {
			if r.Client.IsNotFound(err) {
				_ = r.Repo.MarkDeleted(g.ID)
				continue
			}
			return err
		}
		_ = r.Repo.MarkDeleted(g.ID)
	}
	return nil
}
