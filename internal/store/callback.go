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

func scanCallback(sc interface {
	Scan(dest ...any) error
}) (*Callback, error) {
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
	rows, err := r.db.Query("SELECT "+callbackCols+` FROM es2p_callbacks
		WHERE status = 'pending' AND (next_retry_at IS NULL OR next_retry_at <= ?)
		ORDER BY id LIMIT ?`, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Callback
	for rows.Next() {
		c, err := scanCallback(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
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
