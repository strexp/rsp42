package store

import (
	"database/sql"
	"time"
)

// AuditRepo writes audit rows.
type AuditRepo struct{ db *sql.DB }

// AuditEntry is one audit record.
type AuditEntry struct {
	// ID is the monotonic, never-reused audit cursor (the table declares
	// INTEGER PRIMARY KEY AUTOINCREMENT, so a deletion never frees an id). It
	// is the basis of the incremental sync endpoint (N1).
	ID         int64
	TS         time.Time
	TenantID   string
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
	_, err := r.db.Exec(`INSERT INTO audit_log (ts, tenant_id, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		ts.Unix(), nullStr(e.TenantID), nullStr(e.Actor), nullStr(e.Interface), nullStr(e.Function), nullStr(e.Subject),
		nullStr(e.Outcome), nullStr(e.StatusCode), nullStr(e.RemoteAddr), nullStr(e.DetailJSON))
	return err
}

// AuditFilter constrains an audit listing (all fields optional).
type AuditFilter struct {
	// Tenant matches an exact tenant id; a non-nil pointer to "" selects the
	// platform-default rows (tenant_id IS NULL); nil means "any tenant".
	Tenant    *string
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
	where, args := auditWhere(f)
	clause := buildWhere(where)
	var total int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM audit_log"+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(`SELECT id, ts, tenant_id, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json
		FROM audit_log`+clause+` ORDER BY id DESC LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		e, err := scanAuditRow(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ListAfterID returns up to limit audit entries with id > afterID, oldest
// first. afterID is an exclusive lower bound, which makes the incremental sync
// "at least once" without repeats (N1); the caller resumes from nextAfterId.
func (r *AuditRepo) ListAfterID(f AuditFilter, afterID int64, limit int) ([]*AuditEntry, error) {
	if limit <= 0 {
		limit = 500
	}
	where, args := auditWhere(f)
	where = append(where, "id > ?")
	args = append(args, afterID)
	rows, err := r.db.Query(`SELECT id, ts, tenant_id, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json
		FROM audit_log`+buildWhere(where)+` ORDER BY id ASC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		e, err := scanAuditRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// auditWhere builds the WHERE conditions for an audit filter.
func auditWhere(f AuditFilter) ([]string, []any) {
	var where []string
	var args []any
	add := func(cond string, v any) { where, args = append(where, cond), append(args, v) }
	if f.Tenant != nil {
		if *f.Tenant == "" {
			where = append(where, "tenant_id IS NULL")
		} else {
			add("tenant_id = ?", *f.Tenant)
		}
	}
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
	return where, args
}

// scanAuditRow scans one audit_log row.
func scanAuditRow(sc rowScanner) (*AuditEntry, error) {
	var e AuditEntry
	var tenant, actor, iface, fn, subj, outcome, code, addr, detail sql.NullString
	var ts int64
	if err := sc.Scan(&e.ID, &ts, &tenant, &actor, &iface, &fn, &subj, &outcome, &code, &addr, &detail); err != nil {
		return nil, err
	}
	e.TS = toTime(ts)
	e.TenantID = tenant.String
	e.Actor, e.Interface, e.Function, e.Subject = actor.String, iface.String, fn.String, subj.String
	e.Outcome, e.StatusCode, e.RemoteAddr, e.DetailJSON = outcome.String, code.String, addr.String, detail.String
	return &e, nil
}

// ListBySubject returns recent audit entries for a subject (newest first).
func (r *AuditRepo) ListBySubject(subject string, limit int) ([]*AuditEntry, error) {
	rows, err := r.db.Query(`SELECT id, ts, tenant_id, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json
		FROM audit_log WHERE subject = ? ORDER BY id DESC LIMIT ?`, subject, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		e, err := scanAuditRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
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
	rows, err := r.db.Query(`SELECT id, ts, tenant_id, actor, interface, function, subject, outcome, status_code, remote_addr, detail_json
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*AuditEntry
	for rows.Next() {
		e, err := scanAuditRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

var auditGroupBy = map[string]string{
	"function":  "COALESCE(function,'')",
	"tenant":    "COALESCE(tenant_id,'')",
	"interface": "COALESCE(interface,'')",
	"outcome":   "COALESCE(outcome,'')",
	"actor":     "COALESCE(actor,'')",
	"day":       "strftime('%Y-%m-%d', ts, 'unixepoch')",
}

// Stats returns audit counts grouped by groupBy ("function" by default).
func (r *AuditRepo) Stats(f AuditFilter, groupBy string) ([]StatCount, error) {
	expr, err := statGroupBy(groupBy, auditGroupBy, "function")
	if err != nil {
		return nil, err
	}
	conds, args := auditWhere(f)
	rows, err := r.db.Query(`SELECT `+expr+` AS k, COUNT(*) FROM audit_log`+buildWhere(conds)+
		` GROUP BY k ORDER BY COUNT(*) DESC, k ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []StatCount{}
	for rows.Next() {
		var sc StatCount
		if err := rows.Scan(&sc.Key, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
