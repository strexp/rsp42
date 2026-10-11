package store

import "database/sql"

// NotificationRepo persists received notifications.
type NotificationRepo struct{ db *sql.DB }

// Insert stores a notification.
func (r *NotificationRepo) Insert(n *Notification) error {
	_, err := r.db.Exec(`INSERT INTO notifications
		(eid, seq_number, operation, iccid, transaction_id, final_result_json, signature_ok, received_at, processed)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		nullStr(n.EID), n.SeqNumber, n.Operation, nullStr(n.ICCID), nullStr(n.TransactionID),
		nullStr(n.FinalResultJSON), boolInt(n.SignatureOK), unixNow(), boolInt(n.Processed))
	return err
}

// ListByEID returns notifications for an EID ordered by sequence number.
func (r *NotificationRepo) ListByEID(eid string) ([]*Notification, error) {
	rows, err := r.db.Query(`SELECT id, eid, seq_number, operation, iccid, transaction_id, final_result_json,
		signature_ok, received_at, processed FROM notifications WHERE eid = ? ORDER BY seq_number`, eid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Notification
	for rows.Next() {
		var n Notification
		var eidN, op, iccid, txn, fr sql.NullString
		var sig, proc int
		var received int64
		if err := rows.Scan(&n.ID, &eidN, &n.SeqNumber, &op, &iccid, &txn, &fr, &sig, &received, &proc); err != nil {
			return nil, err
		}
		n.EID, n.Operation, n.ICCID, n.TransactionID, n.FinalResultJSON = eidN.String, op.String, iccid.String, txn.String, fr.String
		n.SignatureOK, n.Processed = sig != 0, proc != 0
		n.ReceivedAt = toTime(received)
		out = append(out, &n)
	}
	return out, rows.Err()
}
