package store

import (
	"database/sql"
	"errors"
	"time"
)

// Idempotency errors.
var (
	// ErrIdempotencyConflict is returned when the same key is reused with a
	// different request payload.
	ErrIdempotencyConflict = errors.New("store: idempotency key reused with a different request")
	// ErrIdempotencyInFlight is returned when the same key is currently being
	// processed by another request.
	ErrIdempotencyInFlight = errors.New("store: idempotency key already in flight")
)

// IdempotencyRecord is a row of the idempotent-replay table.
type IdempotencyRecord struct {
	Key          string
	Endpoint     string
	TenantID     string
	RequestHash  string
	Status       int
	ResponseJSON string
	CreatedAt    time.Time
}

// IdempotencyRepo persists keyed responses so a retried write returns the first
// outcome instead of repeating the side effect (G5).
type IdempotencyRepo struct{ db *sql.DB }

// Claim reserves key/endpoint for the caller.
//
// When it returns replay=true the stored response is final and the caller must
// return it verbatim without running the operation. When replay is false the
// caller owns the key and must finish with Complete (or Abort on failure).
func (r *IdempotencyRepo) Claim(key, endpoint, tenant, requestHash string) (rec *IdempotencyRecord, replay bool, err error) {
	if key == "" {
		return nil, false, errors.New("store: empty idempotency key")
	}
	if existing, gerr := r.Get(key, endpoint); gerr == nil {
		if existing.RequestHash != requestHash {
			return nil, false, ErrIdempotencyConflict
		}
		if existing.ResponseJSON != "" {
			return existing, true, nil
		}
		return nil, false, ErrIdempotencyInFlight
	} else if !errors.Is(gerr, ErrNotFound) {
		return nil, false, gerr
	}

	_, err = r.db.Exec(`INSERT INTO idempotency (key, endpoint, tenant_id, request_hash, status, response_json, created_at)
		VALUES (?,?,?,?,0,'',?)`, key, endpoint, nullStr(tenant), requestHash, unixNow())
	if err != nil {
		// Lost a race: another request claimed the key first.
		existing, gerr := r.Get(key, endpoint)
		if gerr != nil {
			return nil, false, err
		}
		if existing.RequestHash != requestHash {
			return nil, false, ErrIdempotencyConflict
		}
		if existing.ResponseJSON != "" {
			return existing, true, nil
		}
		return nil, false, ErrIdempotencyInFlight
	}
	return &IdempotencyRecord{Key: key, Endpoint: endpoint, TenantID: tenant, RequestHash: requestHash}, false, nil
}

// Complete stores the final status/response for a claimed key.
func (r *IdempotencyRepo) Complete(key, endpoint, tenant string, status int, responseJSON string) error {
	_, err := r.db.Exec(`UPDATE idempotency SET status = ?, response_json = ?, tenant_id = COALESCE(NULLIF(?,''), tenant_id)
		WHERE key = ? AND endpoint = ?`,
		status, responseJSON, tenant, key, endpoint)
	return err
}

// Abort releases a claimed key so a retry can run the operation again. It only
// removes keys that never completed.
func (r *IdempotencyRepo) Abort(key, endpoint string) error {
	_, err := r.db.Exec(`DELETE FROM idempotency WHERE key = ? AND endpoint = ? AND response_json = ''`, key, endpoint)
	return err
}

// Get loads a stored record.
func (r *IdempotencyRepo) Get(key, endpoint string) (*IdempotencyRecord, error) {
	row := r.db.QueryRow(`SELECT key, endpoint, tenant_id, request_hash, status, response_json, created_at
		FROM idempotency WHERE key = ? AND endpoint = ?`, key, endpoint)
	var rec IdempotencyRecord
	var tenant, body sql.NullString
	var created int64
	if err := row.Scan(&rec.Key, &rec.Endpoint, &tenant, &rec.RequestHash, &rec.Status, &body, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rec.TenantID, rec.ResponseJSON, rec.CreatedAt = tenant.String, body.String, toTime(created)
	return &rec, nil
}

// DeleteBefore removes completed records older than ts.
func (r *IdempotencyRepo) DeleteBefore(ts int64) (int64, error) {
	res, err := r.db.Exec(`DELETE FROM idempotency WHERE created_at < ?`, ts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
