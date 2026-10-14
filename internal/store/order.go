package store

import (
	"database/sql"
	"time"
)

// OrderRecord is one row of the order audit log.
type OrderRecord struct {
	TenantID    string
	ICCID       string
	EID         string
	MatchingID  string
	Action      string
	RequestJSON string
	ResultJSON  string
	CreatedAt   time.Time
}

// DeleteBefore removes order audit rows older than ts (retention/GC).
func (r *OrderRepo) DeleteBefore(ts int64) (int64, error) {
	res, err := r.db.Exec(`DELETE FROM orders WHERE created_at < ?`, ts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ListByICCID returns the order audit rows for an ICCID, newest first.
func (r *OrderRepo) ListByICCID(iccid string) ([]*OrderRecord, error) {
	rows, err := r.db.Query(`SELECT COALESCE(tenant_id,''), iccid, eid, matching_id, action, request_json, result_json, created_at
		FROM orders WHERE iccid = ? ORDER BY id DESC`, iccid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*OrderRecord
	for rows.Next() {
		var o OrderRecord
		var tenant, ic, eid, mid, req, res sql.NullString
		var created int64
		if err := rows.Scan(&tenant, &ic, &eid, &mid, &o.Action, &req, &res, &created); err != nil {
			return nil, err
		}
		o.TenantID = tenant.String
		o.ICCID, o.EID, o.MatchingID, o.RequestJSON, o.ResultJSON = ic.String, eid.String, mid.String, req.String, res.String
		o.CreatedAt = toTime(created)
		out = append(out, &o)
	}
	return out, rows.Err()
}

// OrderRepo records ES2+ order actions.
type OrderRepo struct{ db *sql.DB }

// Insert appends an order audit row.
func (r *OrderRepo) Insert(tenant, iccid, eid, matchingID, action, requestJSON, resultJSON string) error {
	_, err := r.db.Exec(`INSERT INTO orders (tenant_id, iccid, eid, matching_id, action, request_json, result_json, created_at)
		VALUES (?,?,?,?,?,?,?,?)`, nullStr(tenant), nullStr(iccid), nullStr(eid), nullStr(matchingID), action, requestJSON, resultJSON, unixNow())
	return err
}
