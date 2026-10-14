package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCallbackRepoListAndRequeue pins N2: the queue is queryable by state,
// tenant and ICCID (the latter two read from the payload JSON), and a
// dead-lettered callback can be re-driven.
func TestCallbackRepoListAndRequeue(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "cb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	enqueue := func(payload string) int64 {
		id, err := st.Callbacks.Enqueue("https://bss.example/es2p", payload, 3)
		require.NoError(t, err)
		return id
	}
	idA := enqueue(`{"tenantId":"carrier-a","iccid":"89000123456789012341","notificationPointId":3}`)
	idB := enqueue(`{"tenantId":"carrier-b","iccid":"89000123456789012342","notificationPointId":4}`)
	idC := enqueue(`{"iccid":"89000123456789012343","notificationPointId":4}`)

	all, total, err := st.Callbacks.ListFiltered(CallbackFilter{}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Len(t, all, 3)

	// Filter by tenant: the payload JSON carries tenantId.
	tenant := "carrier-a"
	items, total, err := st.Callbacks.ListFiltered(CallbackFilter{Tenant: &tenant}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, idA, items[0].ID)

	// An empty tenant selects the platform-default rows.
	empty := ""
	items, total, err = st.Callbacks.ListFiltered(CallbackFilter{Tenant: &empty}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, idC, items[0].ID)

	// Filter by ICCID.
	items, total, err = st.Callbacks.ListFiltered(CallbackFilter{ICCID: "89000123456789012342"}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, idB, items[0].ID)

	// Mark A and B dead-lettered; "dead" is an accepted alias for "failed".
	require.NoError(t, st.Callbacks.MarkFailed(idA, "connection refused"))
	require.NoError(t, st.Callbacks.MarkFailed(idB, "timeout"))
	_, total, err = st.Callbacks.ListFiltered(CallbackFilter{Status: "dead"}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 2, total)

	// Re-queueing a pending/sent callback is a state conflict.
	require.ErrorIs(t, st.Callbacks.Requeue(idC), ErrConflict)
	require.ErrorIs(t, st.Callbacks.Requeue(9999), ErrNotFound)

	// Re-queueing a dead letter resets attempts and puts it back on the queue.
	require.NoError(t, st.Callbacks.Requeue(idA))
	got, err := st.Callbacks.Get(idA)
	require.NoError(t, err)
	require.Equal(t, CallbackPending, got.Status)
	require.Zero(t, got.Attempts)
	require.Empty(t, got.Response)

	// Batch re-drive: only B is left dead-lettered.
	n, err := st.Callbacks.RequeueDead(nil, time.Now().UTC().Add(time.Hour), 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	got, err = st.Callbacks.Get(idB)
	require.NoError(t, err)
	require.Equal(t, CallbackPending, got.Status)

	// With everything re-queued, a tenant-scoped batch re-drive finds nothing.
	scope := "carrier-a"
	n, err = st.Callbacks.RequeueDead(&scope, time.Now().UTC().Add(time.Hour), 100)
	require.NoError(t, err)
	require.Zero(t, n)
}
