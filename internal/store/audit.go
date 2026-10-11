package store

import (
	"database/sql"
	"time"
)

// AuditRepo writes audit rows.
type AuditRepo struct{ db *sql.DB }

// AuditEntry is one audit record.
type AuditEntry struct {
	TS         time.Time
	Actor      string
	Interface  string
	Function   string
	Subject    string
	Outcome    string
	StatusCode string
	RemoteAddr string
	DetailJSON string
}

// Insert stores an audit entry.
func (r *AuditRepo) Insert(e *AuditEntry) error {
	ts := e.TS
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := r.db.Exec(`INSERT INTO audit_log (ts, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		ts.Unix(), nullStr(e.Actor), nullStr(e.Interface), nullStr(e.Function), nullStr(e.Subject),
		nullStr(e.Outcome), nullStr(e.StatusCode), nullStr(e.RemoteAddr), nullStr(e.DetailJSON))
	return err
}

// List returns the most recent audit entries.
func (r *AuditRepo) List(limit int) ([]*AuditEntry, error) {
	rows, err := r.db.Query(`SELECT ts, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var actor, iface, fn, subj, outcome, code, addr, detail sql.NullString
		var ts int64
		if err := rows.Scan(&ts, &actor, &iface, &fn, &subj, &outcome, &code, &addr, &detail); err != nil {
			return nil, err
		}
		e.TS = toTime(ts)
		e.Actor, e.Interface, e.Function, e.Subject = actor.String, iface.String, fn.String, subj.String
		e.Outcome, e.StatusCode, e.RemoteAddr, e.DetailJSON = outcome.String, code.String, addr.String, detail.String
		out = append(out, &e)
	}
	return out, rows.Err()
}
