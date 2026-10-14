package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuditListAfterID pins N1: the cursor is an exclusive lower bound ordered
// by id ascending, and ids are never reused (the table is AUTOINCREMENT), so
// incremental sync is "at least once" without repeats.
func TestAuditListAfterID(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "audit.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	var ids []int64
	for i := 0; i < 5; i++ {
		e := &AuditEntry{Interface: "es9p", Function: "authenticateClient", Outcome: "Executed-Success"}
		require.NoError(t, st.Audit.Insert(e))
		// Insert does not populate ID; read it back through the listing.
		page, err := st.Audit.ListAfterID(AuditFilter{}, 0, 100)
		require.NoError(t, err)
		ids = append(ids, page[len(page)-1].ID)
	}
	require.Len(t, ids, 5)
	require.Equal(t, []int64{1, 2, 3, 4, 5}, ids, "ids are monotonic")

	// First batch, exclusive bound at 0.
	batch, err := st.Audit.ListAfterID(AuditFilter{}, 0, 2)
	require.NoError(t, err)
	require.Len(t, batch, 2)
	require.Equal(t, int64(1), batch[0].ID)
	require.Equal(t, int64(2), batch[1].ID)

	// Resume from the last id: no repeat, no gap.
	batch, err = st.Audit.ListAfterID(AuditFilter{}, batch[len(batch)-1].ID, 2)
	require.NoError(t, err)
	require.Len(t, batch, 2)
	require.Equal(t, int64(3), batch[0].ID)
	require.Equal(t, int64(4), batch[1].ID)

	// Past the end yields an empty batch.
	batch, err = st.Audit.ListAfterID(AuditFilter{}, 5, 10)
	require.NoError(t, err)
	require.Empty(t, batch)

	// Filters combine with the cursor.
	fn := "other"
	batch, err = st.Audit.ListAfterID(AuditFilter{Function: fn}, 0, 10)
	require.NoError(t, err)
	require.Empty(t, batch)
}
