package store

import (
	"database/sql"
	"strings"
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

// AuditFilter constrains an audit listing (all fields optional).
type AuditFilter struct {
	Interface string
	Function  string
	Subject   string
	Actor     string
	Outcome   string
	Since     *time.Time
	Until     *time.Time
}

// ListFiltered returns a page of audit entries (newest first) plus the total.
func (r *AuditRepo) ListFiltered(f AuditFilter, limit, offset int) ([]*AuditEntry, int, error) {
	var where []string
	var args []any
	add := func(cond string, v any) { where, args = append(where, cond), append(args, v) }
	if f.Interface != "" {
		add("interface = ?", f.Interface)
	}
	if f.Function != "" {
		add("function = ?", f.Function)
	}
	if f.Subject != "" {
		add("subject = ?", f.Subject)
	}
	if f.Actor != "" {
		add("actor = ?", f.Actor)
	}
	if f.Outcome != "" {
		add("outcome = ?", f.Outcome)
	}
	if f.Since != nil {
		add("ts >= ?", f.Since.Unix())
	}
	if f.Until != nil {
		add("ts <= ?", f.Until.Unix())
	}
	clause := ""
	if len(where) > 0 {
		clause = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM audit_log"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(`SELECT ts, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json
		FROM audit_log`+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var actor, iface, fn, subj, outcome, code, addr, detail sql.NullString
		var ts int64
		if err := rows.Scan(&ts, &actor, &iface, &fn, &subj, &outcome, &code, &addr, &detail); err != nil {
			return nil, 0, err
		}
		e.TS = toTime(ts)
		e.Actor, e.Interface, e.Function, e.Subject = actor.String, iface.String, fn.String, subj.String
		e.Outcome, e.StatusCode, e.RemoteAddr, e.DetailJSON = outcome.String, code.String, addr.String, detail.String
		out = append(out, &e)
	}
	return out, total, rows.Err()
}

// DeleteBefore removes audit rows older than ts (retention/GC).
func (r *AuditRepo) DeleteBefore(ts int64) (int64, error) {
	res, err := r.db.Exec(`DELETE FROM audit_log WHERE ts < ?`, ts)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
