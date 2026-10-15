package store

import (
	"database/sql"
	"errors"
	"time"
)

// Callback is an outbound ES2+ progress notification persisted for reliable
// delivery (SGP.22 §5.3.5). Status is "pending", "sent" or "failed".
type Callback struct {
	ID          int64
	URL         string
	Payload     string
	PointID     int
	Status      string
	Attempts    int
	NextRetryAt *time.Time
	Response    string
	CreatedAt   time.Time
}

// CallbackRepo persists outbound ES2+ callbacks.
type CallbackRepo struct{ db *sql.DB }

const callbackCols = `id, url, payload_json, notification_point_id, status, attempts, next_retry_at, response, created_at`

func scanCallback(sc rowScanner) (*Callback, error) {
	var c Callback
	var pointID, attempts sql.NullInt64
	var nextRetry sql.NullInt64
	var payload, response sql.NullString
	var created int64
	if err := sc.Scan(&c.ID, &c.URL, &payload, &pointID, &c.Status, &attempts, &nextRetry, &response, &created); err != nil {
		return nil, err
	}
	c.Payload = payload.String
	c.Response = response.String
	c.PointID = int(pointID.Int64)
	c.Attempts = int(attempts.Int64)
	if nextRetry.Valid {
		t := toTime(nextRetry.Int64)
		c.NextRetryAt = &t
	}
	c.CreatedAt = toTime(created)
	return &c, nil
}

// Enqueue stores a pending callback and returns its id.
func (r *CallbackRepo) Enqueue(url, payload string, pointID int) (int64, error) {
	res, err := r.db.Exec(`INSERT INTO es2p_callbacks
		(url, payload_json, notification_point_id, status, attempts, next_retry_at, created_at)
		VALUES (?,?,?,'pending',0,?,?)`, url, payload, pointID, unixNow(), unixNow())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Get loads a callback by id.
func (r *CallbackRepo) Get(id int64) (*Callback, error) {
	row := r.db.QueryRow("SELECT "+callbackCols+" FROM es2p_callbacks WHERE id = ?", id)
	c, err := scanCallback(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// Due returns pending callbacks whose next retry time has passed (or was never
// set), oldest first.
func (r *CallbackRepo) Due(now time.Time, limit int) ([]*Callback, error) {
	if limit <= 0 {
		limit = 100
	}
	return queryAll(r.db, "SELECT "+callbackCols+` FROM es2p_callbacks
		WHERE status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= ?)
		ORDER BY id LIMIT ?`, []any{now.Unix(), limit}, scanCallback)
}

// MarkSent records a successful delivery.
func (r *CallbackRepo) MarkSent(id int64, response string) error {
	_, err := r.db.Exec(`UPDATE es2p_callbacks SET status = 'sent', attempts = attempts + 1, response = ? WHERE id = ?`,
		nullStr(response), id)
	return err
}

// MarkFailed records the final failure of a callback (dead letter).
func (r *CallbackRepo) MarkFailed(id int64, response string) error {
	_, err := r.db.Exec(`UPDATE es2p_callbacks SET status = 'failed', attempts = attempts + 1, response = ? WHERE id = ?`,
		nullStr(response), id)
	return err
}

// MarkRetry records a failed attempt and schedules the next one.
func (r *CallbackRepo) MarkRetry(id int64, next time.Time, response string) error {
	_, err := r.db.Exec(`UPDATE es2p_callbacks SET status = 'pending', attempts = attempts + 1, next_retry_at = ?, response = ? WHERE id = ?`,
		next.Unix(), nullStr(response), id)
	return err
}

// Stats returns the callback queue depth per status.
func (r *CallbackRepo) Stats() (map[string]int, error) {
	rows, err := r.db.Query(`SELECT status, COUNT(*) FROM es2p_callbacks GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// Callback statuses as stored. "dead" is the API-level alias for "failed"
// (the dead letter state).
const (
	CallbackPending = "pending"
	CallbackSent    = "sent"
	CallbackFailed  = "failed"
)

// NormalizeCallbackState maps the API-level state names onto the stored ones.
func NormalizeCallbackState(s string) string {
	if s == "dead" {
		return CallbackFailed
	}
	return s
}

// CallbackFilter constrains a callback listing (all fields optional).
type CallbackFilter struct {
	// Status matches the stored status. "dead" is accepted as an alias for
	// "failed".
	Status string
	// Tenant matches the payload's tenantId. A non-nil pointer to "" selects
	// the platform-default rows (no tenantId); nil means "any tenant".
	Tenant *string
	ICCID  string
	Since  *time.Time
	Until  *time.Time
}

// callbackWhere builds the WHERE conditions for a callback filter. The tenant
// and ICCID filters read the payload JSON (the columns predate tenancy).
func callbackWhere(f CallbackFilter) ([]string, []any) {
	var where []string
	var args []any
	add := func(cond string, v any) { where, args = append(where, cond), append(args, v) }
	if f.Status != "" {
		add("status = ?", NormalizeCallbackState(f.Status))
	}
	if f.Tenant != nil {
		if *f.Tenant == "" {
			where = append(where, "(json_extract(payload_json,'$.tenantId') IS NULL OR json_extract(payload_json,'$.tenantId') = '')")
		} else {
			add("json_extract(payload_json,'$.tenantId') = ?", *f.Tenant)
		}
	}
	if f.ICCID != "" {
		add("json_extract(payload_json,'$.iccid') = ?", f.ICCID)
	}
	if f.Since != nil {
		add("created_at >= ?", f.Since.Unix())
	}
	if f.Until != nil {
		add("created_at <= ?", f.Until.Unix())
	}
	return where, args
}

// ListFiltered returns a page of callbacks (newest first) plus the total.
func (r *CallbackRepo) ListFiltered(f CallbackFilter, limit, offset int) ([]*Callback, int, error) {
	where, args := callbackWhere(f)
	clause := buildWhere(where)
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM es2p_callbacks"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	out, err := queryAll(r.db, "SELECT "+callbackCols+" FROM es2p_callbacks"+clause+
		" ORDER BY id DESC LIMIT ? OFFSET ?", append(args, limit, offset), scanCallback)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// Requeue puts one dead-lettered callback back on the queue, resetting its
// attempt counter. It returns ErrNotFound for an unknown id and ErrConflict
// when the callback is not in the dead-letter (failed) state.
// Requeue returns a dead letter to the queue. The state test and the update are
// a single statement, so two concurrent requeues cannot both read "failed" and
// both reset the attempt counter.
func (r *CallbackRepo) Requeue(id int64) error {
	res, err := r.db.Exec(`UPDATE es2p_callbacks
		SET status = ?, attempts = 0, next_retry_at = ?, response = NULL
		WHERE id = ? AND status = ?`, CallbackPending, unixNow(), id, CallbackFailed)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		// Nothing was requeued: either the row does not exist or it is not a
		// dead letter. Get tells the two apart so the caller keeps the same
		// ErrNotFound / ErrConflict contract.
		if _, err := r.Get(id); err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

func (r *CallbackRepo) RequeueDead(tenant *string, before time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 100
	}
	var where []string
	var args []any
	where = append(where, "status = 'failed'", "created_at <= ?")
	args = append(args, before.Unix())
	if tenant != nil {
		if *tenant == "" {
			where = append(where, "(json_extract(payload_json,'$.tenantId') IS NULL OR json_extract(payload_json,'$.tenantId') = '')")
		} else {
			where = append(where, "json_extract(payload_json,'$.tenantId') = ?")
			args = append(args, *tenant)
		}
	}
	res, err := r.db.Exec(`UPDATE es2p_callbacks
		SET status = 'pending', attempts = 0, next_retry_at = ?, response = NULL
		WHERE id IN (SELECT id FROM es2p_callbacks`+buildWhere(where)+` ORDER BY id LIMIT ?)`,
		append([]any{unixNow()}, append(args, limit)...)...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
