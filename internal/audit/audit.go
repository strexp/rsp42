package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"

	"rsp42/internal/store"
)

// Entry is one audit record.
type Entry struct {
	TS         time.Time
	TenantID   string
	Actor      string
	Interface  string
	Function   string
	Subject    string
	Outcome    string
	StatusCode string
	RemoteAddr string
	Detail     map[string]any
}

// AuditSink persists audit rows. It is defined here (by the consumer) so that
// the SQLite repository stays a detail; *store.AuditRepo satisfies it.
type AuditSink interface {
	Insert(e *store.AuditEntry) error
}

// Logger writes audit entries to the configured sink(s).
type Logger struct {
	repo AuditSink
	file *os.File
	mu   sync.Mutex
}

// New builds a Logger. sink is "db", "file" or "both".
//
// Any other value is an error: it used to produce a logger that wrote nowhere,
// which silently removed the audit trail the configuration asked for.
func New(repo AuditSink, sink, filePath string) (*Logger, error) {
	switch sink {
	case "db", "file", "both":
	default:
		return nil, fmt.Errorf("audit: sink %q is not supported (want db|file|both)", sink)
	}
	l := &Logger{repo: repo}
	if sink == "file" || sink == "both" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit: open %s: %w", filePath, err)
		}
		l.file = f
	}
	if sink == "db" && sinkAbsent(repo) {
		return nil, fmt.Errorf("audit: db sink requires a store")
	}
	return l, nil
}

// Close releases file resources.
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// sinkAbsent reports whether no repository was supplied, including a typed nil
// pointer stored in the interface (which is not == nil).
func sinkAbsent(repo AuditSink) bool {
	if repo == nil {
		return true
	}
	rv := reflect.ValueOf(repo)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}

// Log writes an entry to the enabled sinks.
func (l *Logger) Log(e Entry) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.repo != nil {
		detail := ""
		if len(e.Detail) > 0 {
			if b, err := json.Marshal(e.Detail); err == nil {
				detail = string(b)
			}
		}
		_ = l.repo.Insert(&store.AuditEntry{
			TS: e.TS, TenantID: e.TenantID, Actor: e.Actor, Interface: e.Interface, Function: e.Function,
			Subject: e.Subject, Outcome: e.Outcome, StatusCode: e.StatusCode,
			RemoteAddr: e.RemoteAddr, DetailJSON: detail,
		})
	}
	if l.file != nil {
		if b, err := json.Marshal(map[string]any{
			"ts": e.TS.Format(time.RFC3339), "tenantId": e.TenantID, "actor": e.Actor, "interface": e.Interface,
			"function": e.Function, "subject": e.Subject, "outcome": e.Outcome,
			"statusCode": e.StatusCode, "remoteAddr": e.RemoteAddr, "detail": e.Detail,
		}); err == nil {
			_, _ = l.file.Write(append(b, '\n'))
		}
	}
}
