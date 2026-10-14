package store

import (
	"errors"
	"strings"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write is refused by the current row state
// (e.g. re-queueing a callback that is not in a dead-letter state).
var ErrConflict = errors.New("store: conflict")

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
