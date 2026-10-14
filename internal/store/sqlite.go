package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store wraps the SQLite database and exposes typed repositories.
type Store struct {
	DB        *sql.DB
	Profiles  *ProfileRepo
	Orders    *OrderRepo
	Sessions  *SessionRepo
	Notifs    *NotificationRepo
	Events    *EventRepo
	Callbacks *CallbackRepo
	Regs      *RegistrationRepo
	Audit     *AuditRepo
	UPP       *UPPRepo
	Perso     *PersonalizationRepo
	Batch     *BatchRepo
}

// Open opens the SQLite database at dsn and applies all migrations.
func Open(dsn string) (*Store, error) {
	ensureDSNDir(dsn)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// SQLite serializes writes; a single connection avoids "database is locked".
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}

	s := &Store{DB: db}
	s.Profiles = &ProfileRepo{db: db}
	s.Orders = &OrderRepo{db: db}
	s.Sessions = &SessionRepo{db: db}
	s.Notifs = &NotificationRepo{db: db}
	s.Events = &EventRepo{db: db}
	s.Callbacks = &CallbackRepo{db: db}
	s.Regs = &RegistrationRepo{db: db}
	s.Audit = &AuditRepo{db: db}
	s.UPP = &UPPRepo{db: db}
	s.Perso = &PersonalizationRepo{db: db}
	s.Batch = &BatchRepo{db: db}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.DB.Close() }

// ensureDSNDir creates the parent directory of a file-backed DSN so that SQLite
// does not fail when e.g. `db/rsp42-smdpp.db` is configured but `db/` is absent.
func ensureDSNDir(dsn string) {
	p := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if p == "" || p == ":memory:" || strings.HasPrefix(p, ":memory:") {
		return
	}
	if dir := filepath.Dir(p); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
}
