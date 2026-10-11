package store

import (
	"database/sql"
	"errors"
	"time"
)

// EventRepo persists SM-DS event records.
type EventRepo struct{ db *sql.DB }

const eventCols = `id, eid, event_id, rsp_server_address, caller_oid, forwarding_indicator, cascaded,
	root_event_id, registered_at, expires_at, deleted_at`

func scanEvent(sc interface{ Scan(dest ...any) error }) (*EventRecord, error) {
	var e EventRecord
	var fwd, casc int
	var root sql.NullString
	var registered int64
	var expires, deleted sql.NullInt64
	if err := sc.Scan(&e.ID, &e.EID, &e.EventID, &e.RSPServerAddress, &e.CallerOID, &fwd, &casc,
		&root, &registered, &expires, &deleted); err != nil {
		return nil, err
	}
	e.ForwardingIndicator = fwd != 0
	e.Cascaded = casc != 0
	e.RootEventID = root.String
	e.RegisteredAt = toTime(registered)
	if expires.Valid {
		t := toTime(expires.Int64)
		e.ExpiresAt = &t
	}
	if deleted.Valid {
		t := toTime(deleted.Int64)
		e.DeletedAt = &t
	}
	return &e, nil
}

// Insert stores a new event record. Re-using an (eid,eventID,callerOID) triple
// fails with ErrEventIDInUse, enforcing the "EventID not reusable" rule.
func (r *EventRepo) Insert(e *EventRecord) (int64, error) {
	if e.RegisteredAt.IsZero() {
		e.RegisteredAt = time.Now().UTC()
	}
	var expires any
	if e.ExpiresAt != nil {
		expires = e.ExpiresAt.Unix()
	}
	res, err := r.db.Exec(`INSERT INTO events
		(eid, event_id, rsp_server_address, caller_oid, forwarding_indicator, cascaded, root_event_id, registered_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		e.EID, e.EventID, e.RSPServerAddress, e.CallerOID, boolInt(e.ForwardingIndicator), boolInt(e.Cascaded),
		nullStr(e.RootEventID), e.RegisteredAt.Unix(), expires)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrEventIDInUse
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	e.ID = id
	return id, nil
}

// ErrEventIDInUse indicates that an EventID is already (or was previously) used
// by the same caller for the same EID.
var ErrEventIDInUse = errors.New("store: event id already in use")

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "UNIQUE constraint failed") || contains(err.Error(), "constraint failed")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// GetByKey returns a record regardless of deletion (for reuse checks).
func (r *EventRepo) GetByKey(eid, eventID, callerOID string) (*EventRecord, error) {
	row := r.db.QueryRow("SELECT "+eventCols+" FROM events WHERE eid=? AND event_id=? AND caller_oid=?", eid, eventID, callerOID)
	e, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

// ListByEID returns the active (not deleted) events for an EID, in registration
// order.
func (r *EventRepo) ListByEID(eid string) ([]*EventRecord, error) {
	rows, err := r.db.Query("SELECT "+eventCols+" FROM events WHERE eid=? AND deleted_at IS NULL ORDER BY registered_at, id", eid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return collectEvents(rows)
}

// ListByEIDEventID returns active events matching eid and eventID.
func (r *EventRepo) ListByEIDEventID(eid, eventID string) ([]*EventRecord, error) {
	rows, err := r.db.Query("SELECT "+eventCols+" FROM events WHERE eid=? AND event_id=? AND deleted_at IS NULL ORDER BY registered_at, id", eid, eventID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return collectEvents(rows)
}

// ListAll returns all active events.
func (r *EventRepo) ListAll() ([]*EventRecord, error) {
	rows, err := r.db.Query("SELECT " + eventCols + " FROM events WHERE deleted_at IS NULL ORDER BY registered_at, id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return collectEvents(rows)
}

func collectEvents(rows *sql.Rows) ([]*EventRecord, error) {
	var out []*EventRecord
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SoftDelete marks an event as deleted and returns whether a row was affected.
func (r *EventRepo) SoftDelete(id int64) (bool, error) {
	res, err := r.db.Exec("UPDATE events SET deleted_at=? WHERE id=? AND deleted_at IS NULL", unixNow(), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// HardDelete removes a row (used to roll back a failed cascade registration).
func (r *EventRepo) HardDelete(id int64) error {
	_, err := r.db.Exec("DELETE FROM events WHERE id=?", id)
	return err
}

// GCExpired soft-deletes events whose expiry has passed.
func (r *EventRepo) GCExpired(now time.Time) (int64, error) {
	res, err := r.db.Exec("UPDATE events SET deleted_at=? WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at < ?", now.Unix(), now.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
