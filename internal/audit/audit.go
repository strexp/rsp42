// Package audit implements structured audit logging with db/file sinks.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
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

// Logger writes audit entries to the configured sink(s).
type Logger struct {
	repo *store.AuditRepo
	file *os.File
	mu   sync.Mutex
}

// New builds a Logger. sink is "db", "file" or "both".
func New(repo *store.AuditRepo, sink, filePath string) (*Logger, error) {
	l := &Logger{repo: repo}
	if sink == "file" || sink == "both" {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit: open %s: %w", filePath, err)
		}
		l.file = f
	}
	if sink == "db" && repo == nil {
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
