package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api/common"
	"rsp42/internal/audit"
)

// TestAuditObservesRequestScope is the regression test for a middleware
// ordering defect: middleware.Audit used to wrap the router from the outside,
// while middleware.RequestScope installed the scope on a *copy* of the request
// via r.WithContext. The audit middleware therefore read the original request
// context and recorded an empty actor and tenant for every generic row.
func TestAuditObservesRequestScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.New(nil, "file", path)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	// Attribute the request the way the protocol handlers do, then answer.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		common.SetActor(r.Context(), "requester-1")
		common.SetTenant(r.Context(), "carrier-1")
		w.WriteHeader(http.StatusNoContent)
	})

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := base(log, Options{Audit: l}, "es2p")
	r.Post("/gsma/rsp2/es2plus/downloadOrder", handler)

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/gsma/rsp2/es2plus/downloadOrder", "application/json", nil)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	var row struct {
		Actor    string `json:"actor"`
		TenantID string `json:"tenantId"`
		Function string `json:"function"`
		Outcome  string `json:"outcome"`
	}
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(raw), &row))
	require.Equal(t, "requester-1", row.Actor, "audit actor must come from the request scope")
	require.Equal(t, "carrier-1", row.TenantID, "audit tenant must come from the request scope")
	require.Equal(t, "/gsma/rsp2/es2plus/downloadOrder", row.Function)
	require.Equal(t, "Executed-Success", row.Outcome)
}

// TestAdminRouterSkipsMiddlewareAudit pins that health and metrics scrapes do
// not produce generic audit rows; the management API audits its own writes.
func TestAdminRouterSkipsMiddlewareAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := audit.New(nil, "file", path)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := NewAdminRouter(log, func() bool { return true }, nil, Options{Audit: l})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// audit.New creates the sink file eagerly, so "not audited" means no rows.
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Empty(t, bytes.TrimSpace(raw), "health checks must not be audited by the middleware")
}
