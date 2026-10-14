package store

import (
	"fmt"
	"strings"
)

// StatCount is one aggregate bucket.
type StatCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// statGroupBy maps an API groupBy onto a SQL expression; it returns an error for
// anything outside the whitelist (never interpolate user input blindly).
func statGroupBy(groupBy string, allowed map[string]string, fallback string) (string, error) {
	if groupBy == "" {
		groupBy = fallback
	}
	expr, ok := allowed[groupBy]
	if !ok {
		keys := make([]string, 0, len(allowed))
		for k := range allowed {
			keys = append(keys, k)
		}
		return "", fmt.Errorf("store: unsupported groupBy %q (want %s)", groupBy, strings.Join(keys, "|"))
	}
	return expr, nil
}

// buildWhere assembles an SQL WHERE clause from conditions and args.
func buildWhere(conds []string) string {
	if len(conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(conds, " AND ")
}

var profileGroupBy = map[string]string{
	"state":        "state",
	"tenant":       "COALESCE(tenant_id,'')",
	"profile_type": "COALESCE(profile_type,'')",
	"day":          "strftime('%Y-%m-%d', created_at, 'unixepoch')",
}

// Stats returns profile counts grouped by groupBy ("state" by default).
func (r *ProfileRepo) Stats(f ProfileFilter, groupBy string) ([]StatCount, error) {
	expr, err := statGroupBy(groupBy, profileGroupBy, "state")
	if err != nil {
		return nil, err
	}
	conds, args := profileWhere(f)
	rows, err := r.db.Query(`SELECT `+expr+` AS k, COUNT(*) FROM profiles`+buildWhere(conds)+
		` GROUP BY k ORDER BY COUNT(*) DESC, k ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StatCount
	for rows.Next() {
		var sc StatCount
		if err := rows.Scan(&sc.Key, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
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
	var out []StatCount
	for rows.Next() {
		var sc StatCount
		if err := rows.Scan(&sc.Key, &sc.Count); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}
