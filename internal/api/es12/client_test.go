package es12_test

import (
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api"
	"rsp42/internal/api/es12"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func TestES12RegisterDeleteRoundTrip(t *testing.T) {
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "e12.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	events := service.NewEventService(st.Events, "root", "testrootsmds.example.com", time.Hour)
	srv := httptest.NewServer(api.NewES12Router(slog.Default(), es12.New(slog.Default(), events), api.Options{}))
	defer srv.Close()

	client := service.NewSMDSCClient(srv.URL, "2.999.10", nil)
	eid := "89049032123451234512345678901235"

	require.NoError(t, client.Register(eid, "dp.example.com", "EVT9", true))
	// Idempotent duplicate.
	require.NoError(t, client.Register(eid, "dp.example.com", "EVT9", true))

	recs, err := st.Events.ListByEID(eid)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, "2.999.10", recs[0].CallerOID)

	require.NoError(t, client.Delete(eid, "EVT9"))
	err = client.Delete(eid, "EVT9")
	require.Error(t, err)
	require.True(t, client.IsNotFound(err))
}
