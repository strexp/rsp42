package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUPPRepoSelectAndActivate(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "upp.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	seed := []UPPTemplate{
		{Name: "v21a", SAIPMajor: 2, SAIPMinor: 1, SHA256: "a", Bytes: []byte{1}, Active: true},
		{Name: "v21b", SAIPMajor: 2, SAIPMinor: 1, SHA256: "b", Bytes: []byte{2}, Active: true},
		{Name: "v23", SAIPMajor: 2, SAIPMinor: 3, SHA256: "c", Bytes: []byte{3}, Active: true},
		{Name: "v23off", SAIPMajor: 2, SAIPMinor: 3, SHA256: "d", Bytes: []byte{4}, Active: false},
	}
	for i := range seed {
		require.NoError(t, st.UPP.Upsert(&seed[i]))
	}

	// Greatest active version not exceeding the requested one (tie broken by name).
	best, err := st.UPP.SelectBest(2, 2)
	require.NoError(t, err)
	require.Equal(t, "v21a", best.Name)

	// Nothing qualifies below the lowest template.
	_, err = st.UPP.SelectBest(1, 0)
	require.ErrorIs(t, err, ErrNotFound)

	// Inactive templates are excluded from selection but readable by name.
	any, err := st.UPP.Any()
	require.NoError(t, err)
	require.Equal(t, "v23", any.Name)

	off, err := st.UPP.GetByName("v23off")
	require.NoError(t, err)
	require.False(t, off.Active)
	require.Equal(t, []byte{4}, off.Bytes)

	// Disabling the highest version falls back to the next active one.
	require.NoError(t, st.UPP.SetActive("v23", false))
	any, err = st.UPP.Any()
	require.NoError(t, err)
	require.Equal(t, "v21a", any.Name)

	// Enabling the other 2.3 template makes it the highest active template.
	require.NoError(t, st.UPP.SetActive("v23off", true))
	any, err = st.UPP.Any()
	require.NoError(t, err)
	require.Equal(t, "v23off", any.Name)

	// Metadata listing excludes bytes.
	list, err := st.UPP.List()
	require.NoError(t, err)
	require.Len(t, list, 4)
	for _, x := range list {
		require.Nil(t, x.Bytes)
	}
}
