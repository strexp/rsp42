package store

import (
	"database/sql"
	"time"
)

// RegistrationRepo records events an SM-DP+ has registered at an SM-DS, so the
// SM-DP+ can delete them later (SGP.22 §3.6.3).
type RegistrationRepo struct{ db *sql.DB }

// Registration is a registered event row.
type Registration struct {
	ID                  int64
	TenantID            string
	EID                 string
	EventID             string
	RSPServerAddress    string
	ForwardingIndicator bool
	RegisteredAt        time.Time
	DeletedAt           *time.Time
}

// Insert records a registration.
func (r *RegistrationRepo) Insert(eid, eventID, rspServerAddress string, forwarding bool, tenant string) error {
	_, err := r.db.Exec(`INSERT INTO smds_registrations (eid, event_id, rsp_server_address, forwarding_indicator, tenant_id, registered_at)
		VALUES (?,?,?,?,?,?)`, eid, eventID, rspServerAddress, boolInt(forwarding), nullStr(tenant), unixNow())
	return err
}

// ListActiveByEID returns the active (not deleted) registrations for an EID.
func (r *RegistrationRepo) ListActiveByEID(eid string) ([]*Registration, error) {
	rows, err := r.db.Query(`SELECT id, COALESCE(tenant_id,''), eid, event_id, rsp_server_address, forwarding_indicator, registered_at, deleted_at
		FROM smds_registrations WHERE eid=? AND deleted_at IS NULL ORDER BY id`, eid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Registration
	for rows.Next() {
		var g Registration
		var fwd int
		var registered int64
		var deleted sql.NullInt64
		if err := rows.Scan(&g.ID, &g.TenantID, &g.EID, &g.EventID, &g.RSPServerAddress, &fwd, &registered, &deleted); err != nil {
			return nil, err
		}
		g.ForwardingIndicator = fwd != 0
		g.RegisteredAt = toTime(registered)
		if deleted.Valid {
			t := toTime(deleted.Int64)
			g.DeletedAt = &t
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

// MarkDeleted marks a registration as deleted.
func (r *RegistrationRepo) MarkDeleted(id int64) error {
	_, err := r.db.Exec(`UPDATE smds_registrations SET deleted_at=? WHERE id=?`, unixNow(), id)
	return err
}
