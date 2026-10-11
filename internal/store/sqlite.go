package store

import (
	"database/sql"
	"embed"
	"fmt"

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
}

// Open opens the SQLite database at dsn and applies all migrations.
func Open(dsn string) (*Store, error) {
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
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.DB.Close() }
