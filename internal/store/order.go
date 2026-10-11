package store

import "database/sql"

// OrderRepo records ES2+ order actions.
type OrderRepo struct{ db *sql.DB }

// Insert appends an order audit row.
func (r *OrderRepo) Insert(iccid, eid, matchingID, action, requestJSON, resultJSON string) error {
	_, err := r.db.Exec(`INSERT INTO orders (iccid, eid, matching_id, action, request_json, result_json, created_at)
		VALUES (?,?,?,?,?,?,?)`, nullStr(iccid), nullStr(eid), nullStr(matchingID), action, requestJSON, resultJSON, unixNow())
	return err
}
