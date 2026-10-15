package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// EventRepo persists SM-DS event records.
type EventRepo struct{ db *sql.DB }

const eventCols = `id, COALESCE(tenant_id,''), eid, event_id, rsp_server_address, caller_oid, forwarding_indicator, cascaded,
	root_event_id, COALESCE(iccid,''), COALESCE(matching_id,''), registered_at, expires_at, deleted_at`

func scanEvent(sc rowScanner) (*EventRecord, error) {
	var e EventRecord
	var fwd, casc int
	var root sql.NullString
	var registered int64
	var expires, deleted sql.NullInt64
	if err := sc.Scan(&e.ID, &e.TenantID, &e.EID, &e.EventID, &e.RSPServerAddress, &e.CallerOID, &fwd, &casc,
		&root, &e.ICCID, &e.MatchingID, &registered, &expires, &deleted); err != nil {
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
		(eid, event_id, rsp_server_address, caller_oid, forwarding_indicator, cascaded, root_event_id, registered_at, expires_at,
		 tenant_id, iccid, matching_id)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.EID, e.EventID, e.RSPServerAddress, e.CallerOID, boolInt(e.ForwardingIndicator), boolInt(e.Cascaded),
		nullStr(e.RootEventID), e.RegisteredAt.Unix(), expires,
		nullStr(e.TenantID), nullStr(e.ICCID), nullStr(e.MatchingID))
	if err != nil {
		if IsUniqueViolation(err) {
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
	return queryAll(r.db, "SELECT "+eventCols+" FROM events WHERE eid=? AND deleted_at IS NULL ORDER BY registered_at, id",
		[]any{eid}, scanEvent)
}

// ListByEIDEventID returns active events matching eid and eventID.
func (r *EventRepo) ListByEIDEventID(eid, eventID string) ([]*EventRecord, error) {
	return queryAll(r.db, "SELECT "+eventCols+" FROM events WHERE eid=? AND event_id=? AND deleted_at IS NULL ORDER BY registered_at, id",
		[]any{eid, eventID}, scanEvent)
}

// ListAll returns all active events.
func (r *EventRepo) ListAll() ([]*EventRecord, error) {
	return queryAll(r.db, "SELECT "+eventCols+" FROM events WHERE deleted_at IS NULL ORDER BY registered_at, id",
		nil, scanEvent)
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

// EventFilter constrains an SM-DS event listing (all fields optional).
type EventFilter struct {
	EID        string
	EventID    string
	ICCID      string
	MatchingID string
	// Tenant matches an exact tenant id; a non-nil pointer to "" selects the
	// platform-default rows (tenant_id IS NULL); nil means "any tenant".
	Tenant *string
	Since  *time.Time
	Until  *time.Time
	// Status selects the lifecycle slice: "active" (default), "expired",
	// "deleted" or "any".
	Status string
	// Sort is "registered_at" (default) or "expires_at", optionally prefixed
	// with '-' for ascending order.
	Sort string
}

func eventOrder(sort string) string {
	dir := "DESC"
	col := "registered_at"
	if len(sort) > 0 && sort[0] == '-' {
		dir, sort = "ASC", sort[1:]
	}
	if sort == "expires_at" {
		col = "expires_at"
	}
	return " ORDER BY " + col + " " + dir + ", id " + dir
}

// ListFiltered returns a page of event records plus the total matching count.
func (r *EventRepo) ListFiltered(f EventFilter, limit, offset int, now time.Time) ([]*EventRecord, int, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where, args = append(where, cond), append(args, v) }
	if f.EID != "" {
		add("eid = ?", f.EID)
	}
	if f.EventID != "" {
		add("event_id = ?", f.EventID)
	}
	if f.ICCID != "" {
		add("iccid = ?", f.ICCID)
	}
	if f.MatchingID != "" {
		add("matching_id = ?", f.MatchingID)
	}
	if f.Tenant != nil {
		if *f.Tenant == "" {
			where = append(where, "tenant_id IS NULL")
		} else {
			add("tenant_id = ?", *f.Tenant)
		}
	}
	if f.Since != nil {
		add("registered_at >= ?", f.Since.Unix())
	}
	if f.Until != nil {
		add("registered_at <= ?", f.Until.Unix())
	}
	switch f.Status {
	case "any", "all":
	case "deleted":
		where = append(where, "deleted_at IS NOT NULL")
	case "expired":
		where, args = append(where, "deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at <= ?"), append(args, now.Unix())
	default: // active
		where, args = append(where, "deleted_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"), append(args, now.Unix())
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM events"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	out, err := queryAll(r.db, "SELECT "+eventCols+" FROM events"+clause+eventOrder(f.Sort)+" LIMIT ? OFFSET ?",
		append(args, limit, offset), scanEvent)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// SetCorrelation backfills the tenant/ICCID/matchingId correlation fields of a
// record (used when the tenant is known only after registration).
func (r *EventRepo) SetCorrelation(id int64, tenant, iccid, matchingID string) error {
	_, err := r.db.Exec(`UPDATE events SET tenant_id = ?, iccid = ?, matching_id = ? WHERE id = ?`,
		nullStr(tenant), nullStr(iccid), nullStr(matchingID), id)
	return err
}

// EventRecord is a row of the SM-DS event store (SGP.22 §3.6).
type EventRecord struct {
	ID                  int64
	EID                 string
	EventID             string
	RSPServerAddress    string
	CallerOID           string
	ForwardingIndicator bool
	Cascaded            bool
	RootEventID         string
	// TenantID/ICCID/MatchingID are rsp42-internal correlation fields (the
	// ES12 body is a closed set, so the tenant travels in a request header).
	TenantID     string
	ICCID        string
	MatchingID   string
	RegisteredAt time.Time
	ExpiresAt    *time.Time
	DeletedAt    *time.Time
}
