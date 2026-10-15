package store

import (
	"database/sql"
	"time"
)

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

// ListByICCID returns notifications for an ICCID, newest first.
func (r *NotificationRepo) ListByICCID(iccid string) ([]*Notification, error) {
	rows, err := r.db.Query(`SELECT id, eid, seq_number, operation, iccid, transaction_id, final_result_json,
		signature_ok, received_at, processed FROM notifications WHERE iccid = ? ORDER BY id DESC`, iccid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Notification
	for rows.Next() {
		var n Notification
		var eidN, op, ic, txn, fr sql.NullString
		var sig, proc int
		var received int64
		if err := rows.Scan(&n.ID, &eidN, &n.SeqNumber, &op, &ic, &txn, &fr, &sig, &received, &proc); err != nil {
			return nil, err
		}
		n.EID, n.Operation, n.ICCID, n.TransactionID, n.FinalResultJSON = eidN.String, op.String, ic.String, txn.String, fr.String
		n.SignatureOK, n.Processed = sig != 0, proc != 0
		n.ReceivedAt = toTime(received)
		out = append(out, &n)
	}
	return out, rows.Err()
}

// DeleteBefore removes notifications received before ts (retention/GC).
func (r *NotificationRepo) DeleteBefore(ts int64) (int64, error) {
	res, err := r.db.Exec(`DELETE FROM notifications WHERE received_at < ?`, ts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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

// NotificationFilter constrains a notification listing.
type NotificationFilter struct {
	ICCID string
	EID   string
	Since *time.Time
	Until *time.Time
}

// ListFiltered returns a page of notifications (newest first) plus the total.
func (r *NotificationRepo) ListFiltered(f NotificationFilter, limit, offset int) ([]*Notification, int, error) {
	var where []string
	var args []any
	if f.ICCID != "" {
		where, args = append(where, "iccid = ?"), append(args, f.ICCID)
	}
	if f.EID != "" {
		where, args = append(where, "eid = ?"), append(args, f.EID)
	}
	if f.Since != nil {
		where, args = append(where, "received_at >= ?"), append(args, f.Since.Unix())
	}
	if f.Until != nil {
		where, args = append(where, "received_at <= ?"), append(args, f.Until.Unix())
	}
	clause := buildWhere(where)
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM notifications"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(`SELECT id, eid, seq_number, operation, iccid, transaction_id, final_result_json,
		signature_ok, received_at, processed FROM notifications`+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Notification
	for rows.Next() {
		var n Notification
		var eidN, op, ic, txn, fr sql.NullString
		var sig, proc int
		var received int64
		if err := rows.Scan(&n.ID, &eidN, &n.SeqNumber, &op, &ic, &txn, &fr, &sig, &received, &proc); err != nil {
			return nil, 0, err
		}
		n.EID, n.Operation, n.ICCID, n.TransactionID, n.FinalResultJSON = eidN.String, op.String, ic.String, txn.String, fr.String
		n.SignatureOK, n.Processed = sig != 0, proc != 0
		n.ReceivedAt = toTime(received)
		out = append(out, &n)
	}
	return out, total, rows.Err()
}

// Notification is a received notification row.
type Notification struct {
	ID              int64
	EID             string
	SeqNumber       int64
	Operation       string
	ICCID           string
	TransactionID   string
	FinalResultJSON string
	SignatureOK     bool
	ReceivedAt      time.Time
	Processed       bool
}
