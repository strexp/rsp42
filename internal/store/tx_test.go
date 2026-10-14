package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open("file:" + filepath.Join(t.TempDir(), "store.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// TestUpsertArchivedKeepsHistory pins the archive/upsert transaction: the
// previous revision is recorded before the live row is replaced, and the
// version number advances.
func TestUpsertArchivedKeepsHistory(t *testing.T) {
	st := newTestStore(t)
	const name = "ts48"

	mk := func(sha string, body byte) *UPPTemplate {
		return &UPPTemplate{Name: name, SAIPMajor: 2, SAIPMinor: 3, SHA256: sha, Bytes: []byte{body}, Active: true}
	}

	require.NoError(t, st.UPP.UpsertArchived(mk("sha-1", 1), "first"))
	require.NoError(t, st.UPP.UpsertArchived(mk("sha-2", 2), "second"))
	require.NoError(t, st.UPP.UpsertArchived(mk("sha-3", 3), "third"))

	live, err := st.UPP.GetScoped("", name)
	require.NoError(t, err)
	require.Equal(t, "sha-3", live.SHA256)
	require.Equal(t, []byte{3}, live.Bytes)

	versions, err := st.UPP.ListVersions("", name)
	require.NoError(t, err)
	require.Len(t, versions, 2, "each replacement archives exactly one previous revision")
	// The note passed to UpsertArchived describes the replacement that caused
	// the archive, so it is attached to the revision being replaced.
	require.Equal(t, 2, versions[0].VersionNo)
	require.Equal(t, "sha-2", versions[0].SHA256)
	require.Equal(t, "third", versions[0].Note)
	require.Equal(t, 1, versions[1].VersionNo)
	require.Equal(t, "sha-1", versions[1].SHA256)
	require.Equal(t, "second", versions[1].Note)
}

// TestUpsertPreservesCreatedAt pins the ON CONFLICT behaviour of the single
// statement upsert: replacing a template keeps its original creation time while
// the mutable columns are updated.
func TestUpsertPreservesCreatedAt(t *testing.T) {
	st := newTestStore(t)
	created := time.Unix(1_600_000_000, 0).UTC()

	first := &UPPTemplate{Name: "t", SAIPMajor: 2, SAIPMinor: 3, SHA256: "a", Bytes: []byte{1}, Active: true, CreatedAt: created}
	require.NoError(t, st.UPP.Upsert(first))

	// Replace with a fresh row (zero CreatedAt): created_at must not move.
	second := &UPPTemplate{Name: "t", SAIPMajor: 2, SAIPMinor: 3, SHA256: "b", Bytes: []byte{2}, Active: false}
	require.NoError(t, st.UPP.Upsert(second))

	got, err := st.UPP.GetScoped("", "t")
	require.NoError(t, err)
	require.Equal(t, "b", got.SHA256)
	require.Equal(t, []byte{2}, got.Bytes)
	require.False(t, got.Active)
	require.Equal(t, created.Unix(), got.CreatedAt.Unix(), "created_at must survive an upsert")
}

// TestWithTxRollsBack pins the transaction helper: an error from fn discards
// every statement it made.
func TestWithTxRollsBack(t *testing.T) {
	st := newTestStore(t)
	sentinel := errors.New("boom")

	err := withTx(st.DB, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO tenants (id, name, created_at, updated_at) VALUES ('t1','T1',0,0)`); err != nil {
			return err
		}
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)
	_, err = st.Tenants.Get("t1")
	require.ErrorIs(t, err, ErrNotFound, "the rolled-back row must not exist")

	// A successful function commits.
	require.NoError(t, withTx(st.DB, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO tenants (id, name, created_at, updated_at) VALUES ('t2','T2',0,0)`)
		return err
	}))
	_, err = st.Tenants.Get("t2")
	require.NoError(t, err)
}
