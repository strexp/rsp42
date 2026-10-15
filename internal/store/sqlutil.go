package store

import (
	"fmt"
	"strings"
	"time"
)

// SQL conversion helpers shared by the repositories: the schema stores times as
// Unix seconds and empty strings as NULL.

func unixNow() int64 { return time.Now().Unix() }

func toTime(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

func nullStr(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Unix()
}

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

// queryAll runs q and scans every row with scan, replacing the hand-rolled
// `for rows.Next()` loop the repositories used to repeat. It returns a nil
// slice when the query matches nothing, which is what those loops returned.
func queryAll[T any](db dbtx, q string, args []any, scan func(rowScanner) (T, error)) ([]T, error) {
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
