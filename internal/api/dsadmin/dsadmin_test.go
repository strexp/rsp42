package dsadmin_test

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"rsp42/internal/api/dsadmin"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

func newDSTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "ds.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	r := chi.NewRouter()
	dsadmin.Mount(r, dsadmin.Config{Events: st.Events, Audit: st.Audit, DefaultTTL: time.Hour})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, st
}

// TestAdminDSEventWrite pins N8: the SM-DS admin can register and delete
// events for the edge cases where esim42 cannot use ES12.
func TestAdminDSEventWrite(t *testing.T) {
	srv, st := newDSTestServer(t)
	base := srv.URL + "/admin/api/v1"

	eid := "89049032000000000000000000000001"
	status, raw := testutil.DoJSON(t, "POST", base+"/events", map[string]any{
		"eid": eid, "eventId": "EVT-1", "rspServerAddress": "smdp.example",
		"tenant": "carrier-a", "iccid": "89000123456789012341",
	})
	require.Equal(t, 201, status, string(raw))
	var created map[string]any
	require.NoError(t, json.Unmarshal(raw, &created))
	require.Equal(t, "EVT-1", created["eventId"])
	require.Equal(t, "carrier-a", created["tenant"])
	require.NotNil(t, created["expiresAt"], "the configured DefaultTTL applies")
	id := int64(created["id"].(float64))

	// The write is audited.
	audits, err := st.Audit.ListBySubject(eid, 10)
	require.NoError(t, err)
	require.Len(t, audits, 1)
	require.Equal(t, "registerEvent", audits[0].Function)

	// Re-using the EventID for the same EID is refused.
	status, raw = testutil.DoJSON(t, "POST", base+"/events", map[string]any{"eid": eid, "eventId": "EVT-1", "rspServerAddress": "smdp.example"})
	require.Equal(t, 409, status, string(raw))
	require.Contains(t, string(raw), "event_id_in_use")

	// An omitted EventID is generated.
	status, raw = testutil.DoJSON(t, "POST", base+"/events", map[string]any{"eid": "89049032000000000000000000000002", "rspServerAddress": "smdp.example"})
	require.Equal(t, 201, status, string(raw))
	require.Contains(t, string(raw), `"eventId":"EVT-`)

	// Missing mandatory fields.
	status, _ = testutil.DoJSON(t, "POST", base+"/events", map[string]any{"eid": "x"})
	require.Equal(t, 400, status)

	// Delete soft-deletes; a second delete is a 404.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/events/"+strconv.FormatInt(id, 10), nil)
	require.Equal(t, 204, status)
	status, _ = testutil.DoJSON(t, "DELETE", base+"/events/"+strconv.FormatInt(id, 10), nil)
	require.Equal(t, 404, status)

	// The record is still listed with a deletedAt marker.
	status, raw = testutil.DoJSON(t, "GET", base+"/events?status=deleted", nil)
	require.Equal(t, 200, status, string(raw))
	require.Contains(t, string(raw), `"deletedAt"`)
}

// TestDSAdminOpenAPIIsScopedToMountedRoutes pins the fix for the SM-DS admin
// serving the SM-DP+ document: the DS surface must describe only what it mounts
// (/events), not the SM-DP+ resources it does not serve.
func TestDSAdminOpenAPIIsScopedToMountedRoutes(t *testing.T) {
	srv, _ := newDSTestServer(t)
	status, raw := testutil.DoJSON(t, "GET", srv.URL+"/admin/api/v1/openapi.json", nil)
	require.Equal(t, 200, status)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	paths, ok := doc["paths"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, paths, "/admin/api/v1/events")
	require.Contains(t, paths, "/admin/api/v1/events/{id}")
	for _, absent := range []string{"/admin/api/v1/profiles", "/admin/api/v1/upp", "/admin/api/v1/tenants"} {
		require.NotContains(t, paths, absent, "the SM-DS admin must not advertise %s", absent)
	}

	info, ok := doc["info"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, info["title"], "SM-DS")
}
