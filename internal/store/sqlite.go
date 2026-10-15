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
	Pool      *PoolRepo
	Tenants   *TenantRepo
	Idem      *IdempotencyRepo
}

// Open opens the SQLite database at dsn and applies all migrations. All
// transactions are started in IMMEDIATE mode (G12): the write path is
// read-then-update in several places (pool reservation, idempotency claim), and
// a deferred transaction that upgrades its lock can fail with SQLITE_BUSY.
func Open(dsn string) (*Store, error) {
	dsn = applyDSNDefaults(dsn)
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
	s.Pool = &PoolRepo{db: db}
	s.Tenants = &TenantRepo{db: db}
	s.Idem = &IdempotencyRepo{db: db}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.DB.Close() }

// applyDSNDefaults adds the connection settings rsp42 relies on when the
// configured DSN does not carry them:
//
//   - `_txlock=immediate`, because the write path is read-then-update in several
//     places (pool reservation, idempotency claim) and a deferred transaction
//     that upgrades its lock can fail with SQLITE_BUSY;
//   - `journal_mode(WAL)` and `busy_timeout(5000)`, because the server and the
//     `rsp42 admin` commands open the same database file from separate
//     processes, so a DSN without them answers SQLITE_BUSY immediately instead
//     of waiting. The shipped defaults and config.example.yaml already set both;
//     this covers a hand-written DSN.
//
// A private in-memory database gets none of them: WAL does not apply to
// `:memory:`, and no second process can contend for it.
func applyDSNDefaults(dsn string) string {
	if isMemoryDSN(dsn) {
		return dsn
	}
	add := make([]string, 0, 3)
	if !strings.Contains(dsn, "_txlock=") {
		add = append(add, "_txlock=immediate")
	}
	if !strings.Contains(dsn, "journal_mode") {
		add = append(add, "_pragma=journal_mode(WAL)")
	}
	if !strings.Contains(dsn, "busy_timeout") {
		add = append(add, "_pragma=busy_timeout(5000)")
	}
	if len(add) == 0 {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.Join(add, "&")
}

// isMemoryDSN reports whether the DSN names an in-memory database, in either the
// `:memory:` or the `file::memory:` form.
func isMemoryDSN(dsn string) bool {
	return strings.HasPrefix(dsn, ":memory:") || strings.Contains(dsn, ":memory:")
}

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
