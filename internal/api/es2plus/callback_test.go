package es2plus_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/client/es2p"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func newCallbackStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "cb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestCallbackQueueRetriesThenSucceeds(t *testing.T) {
	st := newCallbackStore(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cb := es2p.NewCallbackClient(srv.URL, "2.999.10", nil)
	q := es2p.NewCallbackQueue(st.Callbacks, cb, es2p.QueueOptions{
		Log:     slog.Default(),
		Backoff: func(int) time.Duration { return 0 }, // retry immediately
	})

	// The first delivery fails and is persisted as pending.
	err := q.Deliver(context.Background(), service.ProgressInfo{EID: "89049032123451234512345678901235", ICCID: "8900012345678901234", NotificationPointID: 4, NotificationPointStatus: service.PointStatus{Status: "Executed-Success"}})
	require.Error(t, err)

	due, err := st.Callbacks.Due(time.Now().UTC().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.Equal(t, "pending", due[0].Status)
	require.Equal(t, 1, due[0].Attempts)

	// The retry sweep delivers it.
	n, err := q.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	got, err := st.Callbacks.Get(due[0].ID)
	require.NoError(t, err)
	require.Equal(t, "sent", got.Status)
	require.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

func TestCallbackQueueDeadLetter(t *testing.T) {
	st := newCallbackStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cb := es2p.NewCallbackClient(srv.URL, "2.999.10", nil)
	q := es2p.NewCallbackQueue(st.Callbacks, cb, es2p.QueueOptions{
		Log:         slog.Default(),
		MaxAttempts: 2,
		Backoff:     func(int) time.Duration { return 0 },
	})

	require.Error(t, q.Deliver(context.Background(), service.ProgressInfo{EID: "", ICCID: "8900012345678901234", NotificationPointID: 4, NotificationPointStatus: service.PointStatus{Status: "Failed"}}))
	_, err := q.RunOnce(context.Background())
	require.NoError(t, err)

	// No row is pending any more, and the row is marked as a dead letter.
	due, err := st.Callbacks.Due(time.Now().UTC().Add(time.Hour), 10)
	require.NoError(t, err)
	require.Empty(t, due)

	var status string
	var attempts int
	require.NoError(t, st.DB.QueryRow("SELECT status, attempts FROM es2p_callbacks ORDER BY id LIMIT 1").Scan(&status, &attempts))
	require.Equal(t, "failed", status)
	require.Equal(t, 2, attempts)
}
