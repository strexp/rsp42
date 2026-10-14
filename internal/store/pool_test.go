package store

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPoolImportReserveRelease(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "pool.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	id, inserted, _, err := st.Pool.ImportRange("", "8900012000000000000", "8900012000000000099", "test range")
	require.NoError(t, err)
	require.NotZero(t, id)
	require.Greater(t, inserted, 0, "expected some Luhn-valid ICCIDs")

	// Reserve one.
	iccid, err := st.Pool.Reserve("", "89049032123451234512345678901235", "ref-1", time.Hour)
	require.NoError(t, err)
	require.NotEmpty(t, iccid)

	got, total, err := st.Pool.ListPage("allocated", "", nil, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, iccid, got[0].ICCID)
	require.Equal(t, "89049032123451234512345678901235", got[0].EID)

	// Release then block.
	require.NoError(t, st.Pool.SetState(iccid, "available", ""))
	require.NoError(t, st.Pool.SetState(iccid, "blocked", "reserved for ops"))

	counts, ranges, err := st.Pool.Stats(nil)
	require.NoError(t, err)
	require.Equal(t, 1, ranges)
	require.GreaterOrEqual(t, counts["blocked"], 1)
	require.GreaterOrEqual(t, counts["available"], 1)

	// Round-trip a second import does not duplicate.
	_, inserted2, skipped2, err := st.Pool.ImportRange("", "8900012000000000000", "8900012000000000099", "")
	require.NoError(t, err)
	require.Zero(t, inserted2)
	require.Greater(t, skipped2, 0)

	// Deleting the range removes its available entries.
	removed, err := st.Pool.DeleteRange(id)
	require.NoError(t, err)
	require.GreaterOrEqual(t, removed, 1)
}

// TestPoolConcurrentReserve covers the G6 acceptance criterion: concurrent
// reservations never hand out the same ICCID and never fail with a lock error.
func TestPoolConcurrentReserve(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "concurrent.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	_, inserted, _, err := st.Pool.ImportRange("carrier-a", "8900012000000000000", "8900012000000009999", "")
	require.NoError(t, err)
	require.GreaterOrEqual(t, inserted, 200)

	const workers = 200
	results := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			iccid, err := st.Pool.Reserve("carrier-a", "", "", time.Hour)
			if err != nil {
				errs <- err
				return
			}
			results <- iccid
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent reserve failed: %v", err)
	}
	seen := map[string]bool{}
	for iccid := range results {
		require.False(t, seen[iccid], "ICCID %s handed out twice", iccid)
		seen[iccid] = true
	}
	require.Len(t, seen, workers)

	counts, _, err := st.Pool.Stats(&[]string{"carrier-a"}[0])
	require.NoError(t, err)
	require.Equal(t, workers, counts["allocated"])
}

// TestPoolBlockedICCIDAndClaim covers the operator-supplied-ICCID path: a
// blocked pool entry is never issued, and claiming a still-available entry
// marks it allocated with its owning profile.
func TestPoolBlockedICCIDAndClaim(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "blocked.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	_, _, _, err = st.Pool.ImportRange("carrier-a", "8900012000000000000", "8900012000000000099", "")
	require.NoError(t, err)

	entries, _, err := st.Pool.ListPage("available", "", nil, 2, 0)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	blocked := entries[0].ICCID
	free := entries[1].ICCID

	require.NoError(t, st.Pool.SetState(blocked, "blocked", "ops"))
	state, err := st.Pool.State(blocked)
	require.NoError(t, err)
	require.Equal(t, "blocked", state)

	_, err = st.Pool.State("89999999999999999999")
	require.ErrorIs(t, err, ErrNotFound)

	// Claiming an available entry allocates it.
	require.NoError(t, st.Pool.Claim(free, 7))
	state, err = st.Pool.State(free)
	require.NoError(t, err)
	require.Equal(t, "allocated", state)

	items, _, err := st.Pool.ListPage("allocated", free, nil, 1, 0)
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.NotNil(t, items[0].ProfileID)
	require.Equal(t, int64(7), *items[0].ProfileID)
	require.NotNil(t, items[0].AllocatedAt)
	require.Nil(t, items[0].ReservedUntil)

	// Claiming a blocked entry leaves it blocked.
	require.NoError(t, st.Pool.Claim(blocked, 8))
	state, err = st.Pool.State(blocked)
	require.NoError(t, err)
	require.Equal(t, "blocked", state)
}

// TestReleaseExpiredSkipsOwnedEntries pins the pool invariant that an entry
// which already owns a profile is never reclaimed by the reservation GC, even
// if a reservation deadline is still present: re-issuing it would hand out an
// ICCID that a profile row still references.
func TestReleaseExpiredSkipsOwnedEntries(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "expired.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	_, _, _, err = st.Pool.ImportRange("carrier-a", "8900012000000000000", "8900012000000000099", "")
	require.NoError(t, err)

	entries, _, err := st.Pool.ListPage("available", "", nil, 2, 0)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	owned, lapsed := entries[0].ICCID, entries[1].ICCID

	// Simulate the state the guard defends against: an allocated entry that
	// owns a profile AND still carries a lapsed reservation deadline.
	past := time.Now().UTC().Add(-time.Hour).Unix()
	_, err = st.DB.Exec(`UPDATE iccid_pool SET state='allocated', profile_id=42, reserved_until=? WHERE iccid=?`, past, owned)
	require.NoError(t, err)
	_, err = st.DB.Exec(`UPDATE iccid_pool SET state='allocated', profile_id=NULL, reserved_until=? WHERE iccid=?`, past, lapsed)
	require.NoError(t, err)

	n, err := st.Pool.ReleaseExpired(time.Now().UTC())
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "only the unowned reservation may be reclaimed")

	state, err := st.Pool.State(owned)
	require.NoError(t, err)
	require.Equal(t, "allocated", state, "an entry owning a profile must stay allocated")

	state, err = st.Pool.State(lapsed)
	require.NoError(t, err)
	require.Equal(t, "available", state, "a lapsed unowned reservation must be reclaimed")
}
