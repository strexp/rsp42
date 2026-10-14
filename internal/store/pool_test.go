package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoolImportReserveRelease(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "pool.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	id, inserted, _, err := st.Pool.ImportRange("8900012000000000000", "8900012000000000099", "test range")
	require.NoError(t, err)
	require.NotZero(t, id)
	require.Greater(t, inserted, 0, "expected some Luhn-valid ICCIDs")

	// Reserve one.
	iccid, err := st.Pool.Reserve("89049032123451234512345678901235")
	require.NoError(t, err)
	require.NotEmpty(t, iccid)

	got, total, err := st.Pool.ListPage("allocated", "", 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, iccid, got[0].ICCID)
	require.Equal(t, "89049032123451234512345678901235", got[0].EID)

	// Release then block.
	require.NoError(t, st.Pool.SetState(iccid, "available", ""))
	require.NoError(t, st.Pool.SetState(iccid, "blocked", "reserved for ops"))

	counts, ranges, err := st.Pool.Stats()
	require.NoError(t, err)
	require.Equal(t, 1, ranges)
	require.GreaterOrEqual(t, counts["blocked"], 1)
	require.GreaterOrEqual(t, counts["available"], 1)

	// Round-trip a second import does not duplicate.
	_, inserted2, skipped2, err := st.Pool.ImportRange("8900012000000000000", "8900012000000000099", "")
	require.NoError(t, err)
	require.Zero(t, inserted2)
	require.Greater(t, skipped2, 0)

	// Deleting the range removes its available entries.
	removed, err := st.Pool.DeleteRange(id)
	require.NoError(t, err)
	require.GreaterOrEqual(t, removed, 1)
}
