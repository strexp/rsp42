package store

import (
	"errors"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write is refused by the current row state
// (e.g. re-queueing a callback that is not in a dead-letter state).
var ErrConflict = errors.New("store: conflict")

// IsUniqueViolation reports whether err is a SQLite PRIMARY KEY/UNIQUE
// constraint failure, using the driver's typed result code rather than the
// error message (whose wording is not part of any contract).
func IsUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	default:
		return false
	}
}
