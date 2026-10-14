package store

import "database/sql"

// dbtx is the subset of *sql.DB and *sql.Tx that the repositories use, so a
// helper can serve both a direct call and a call inside a transaction.
type dbtx interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// rowScanner is the subset of *sql.Row and *sql.Rows the scan helpers need.
type rowScanner interface{ Scan(dest ...any) error }

// withTx runs fn in one transaction: it commits on success and rolls back on
// error or panic. The DSN sets `_txlock=immediate` (see Open), so a write
// transaction takes its lock up front and a read-then-write sequence inside it
// cannot interleave with another writer.
func withTx(db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
