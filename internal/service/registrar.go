package service

import (
	"encoding/json"
	"log/slog"

	"rsp42/internal/client/es12"
	"rsp42/internal/metrics"
	"rsp42/internal/store"
)

// Registrar registers and deletes SM-DS events on behalf of the SM-DP+
// (SGP.22 §3.6.1 / §3.6.3) and records them for later deletion.
//
// Every caller that fails to register or delete an event is reported the same
// way, through Metrics and Audit when they are set: the counters and the audit
// row would otherwise have to be repeated by each caller (ConfirmOrder,
// CancelOrder, the ACR-0 MatchingID rotation and the install-time deletion).
type Registrar struct {
	Repo        RegistrationStore
	Client      *es12.SMDSCClient
	SMDPAddress string
	Forwarding  bool
	Log         *slog.Logger
	// Metrics and Audit, when set, make a failure observable:
	// rsp42_es12_register_failures_total and an interface=es12 audit row.
	Metrics *metrics.Registry
	Audit   AuditSink
}

// Register generates an event for the EID and registers it at the SM-DS.
// eventID is normally the profile's matchingId.
//
// Registering an event that is already active for the EID is a no-op: a
// ConfirmOrder resend must not be answered by the SM-DS with "EventID already in
// use" and counted as a registration failure (Table 27's resend NOTE expects a
// resend to take no other action).
func (r *Registrar) Register(eid, eventID, smdsAddress string, meta es12.EventMeta) error {
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
		r.recordFailure("registerEvent", meta.Tenant, eid, meta.ICCID, err)
		return err
	}
	return r.Repo.Insert(eid, eventID, smdsAddress, r.Forwarding, meta.Tenant)
}

// DeleteForEID deletes every active registration for the EID at the SM-DS.
func (r *Registrar) DeleteForEID(eid string, meta es12.EventMeta) error {
	return r.deleteMatching(eid, meta, nil)
}

// DeleteEvent deletes the registration held under one event id (normally the
// MatchingID it was registered for) at the SM-DS. It is a no-op when nothing is
// registered under that id. Callers use it when a Profile's MatchingID changes:
// the registration is keyed by the MatchingID, so the previous one no longer
// matches the order (SGP.22 §3.6).
func (r *Registrar) DeleteEvent(eid, eventID string, meta es12.EventMeta) error {
	if eventID == "" {
		return nil
	}
	return r.deleteMatching(eid, meta, func(g *store.Registration) bool { return g.EventID == eventID })
}

// deleteMatching removes the active registrations selected by keep (all of them
// when keep is nil).
func (r *Registrar) deleteMatching(eid string, meta es12.EventMeta, keep func(*store.Registration) bool) error {
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
			r.recordFailure("deleteEvent", meta.Tenant, eid, meta.ICCID, err)
			return err
		}
		_ = r.Repo.MarkDeleted(g.ID)
	}
	return nil
}

// recordFailure counts and audits one failed registration or deletion. The
// audit row is written with interface=es12 even though it may have been caused
// by an ES2+ call (ConfirmOrder/CancelOrder), because the failing interaction is
// the ES12 one.
func (r *Registrar) recordFailure(function, tenant, eid, iccid string, err error) {
	if r.Metrics != nil {
		r.Metrics.Inc("rsp42_es12_register_failures_total", map[string]string{"tenant": tenant})
	}
	if r.Audit == nil {
		return
	}
	detail, _ := json.Marshal(map[string]string{"eid": eid, "iccid": iccid, "error": err.Error()})
	_ = r.Audit.Insert(&store.AuditEntry{
		TenantID: tenant, Interface: "es12", Function: function, Subject: eid,
		Outcome: "Failed", DetailJSON: string(detail),
	})
}
