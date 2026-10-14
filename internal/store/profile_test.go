package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProfileListSortByTenant pins N7: "tenant" is part of the sort whitelist
// and orders by the platform-default-normalised owner.
func TestProfileListSortByTenant(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "profiles.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	for _, seed := range []struct{ iccid, tenant string }{
		{"89000123456789012341", "carrier-b"},
		{"89000123456789012342", ""},
		{"89000123456789012343", "carrier-a"},
	} {
		_, err := st.Profiles.Create(&Profile{ICCID: seed.iccid, TenantID: seed.tenant, State: StateAllocated})
		require.NoError(t, err)
	}

	// In this API a bare sort name is descending and a "-" prefix is ascending.
	asc, total, err := st.Profiles.ListFiltered(ProfileFilter{}, 10, 0, "-tenant")
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Equal(t, "", asc[0].TenantID, "the platform-default scope sorts first")
	require.Equal(t, "carrier-a", asc[1].TenantID)
	require.Equal(t, "carrier-b", asc[2].TenantID)

	desc, _, err := st.Profiles.ListFiltered(ProfileFilter{}, 10, 0, "tenant")
	require.NoError(t, err)
	require.Equal(t, "carrier-b", desc[0].TenantID)
	require.Equal(t, "", desc[2].TenantID)

	// An unknown sort falls back to the default instead of erroring.
	_, total, err = st.Profiles.ListFiltered(ProfileFilter{}, 10, 0, "nonsense")
	require.NoError(t, err)
	require.Equal(t, 3, total)
}
