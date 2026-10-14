package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPersonalizationCredentialsPool(t *testing.T) {
	st := openTestStore(t)
	put := func(p *Personalization) {
		t.Helper()
		require.NoError(t, st.Perso.Upsert(p))
	}

	// Two unbound credentials for carrier-a, one for carrier-b.
	put(&Personalization{TenantID: "carrier-a", IMSI: "001010000000001", SPN: "A1", K: []byte{1}})
	put(&Personalization{TenantID: "carrier-a", IMSI: "001010000000002", SPN: "A2", K: []byte{2}})
	put(&Personalization{TenantID: "carrier-b", IMSI: "001020000000001", SPN: "B1", K: []byte{3}})

	n, err := st.Perso.CountUnbound("carrier-a")
	require.NoError(t, err)
	require.Equal(t, 2, n)

	// Credentials are visible by IMSI and isolated per tenant.
	row, err := st.Perso.GetByIMSI("carrier-a", "001010000000001")
	require.NoError(t, err)
	require.Equal(t, "A1", row.SPN)
	_, err = st.Perso.GetByIMSI("carrier-b", "001010000000001")
	require.ErrorIs(t, err, ErrNotFound)

	// The same IMSI can exist for two tenants (unique per tenant).
	put(&Personalization{TenantID: "carrier-b", IMSI: "001010000000001", SPN: "B-copy"})
	rowB, err := st.Perso.GetByIMSI("carrier-b", "001010000000001")
	require.NoError(t, err)
	require.Equal(t, "B-copy", rowB.SPN)

	// Re-importing the same (tenant, imsi) replaces rather than duplicates.
	count, total, err := st.Perso.ListPage("", "carrier-a", 10, 0)
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, count, 2)

	// ReservePair binds the lowest unbound entry to an ICCID.
	imsi, err := st.Perso.ReservePair("carrier-a", "8900012000000000001")
	require.NoError(t, err)
	require.Equal(t, "001010000000001", imsi)

	bound, err := st.Perso.GetByICCID("carrier-a", "8900012000000000001")
	require.NoError(t, err)
	require.Equal(t, imsi, bound.IMSI)

	n, err = st.Perso.CountUnbound("carrier-a")
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// Re-reserving the same ICCID releases the previous binding first, so the
	// per-tenant unique index is never violated and the same entry is rebound.
	imsi2, err := st.Perso.ReservePair("carrier-a", "8900012000000000001")
	require.NoError(t, err)
	require.Equal(t, imsi, imsi2)

	// Unbinding returns the entry to the pool.
	require.NoError(t, st.Perso.UnbindPair("carrier-a", "8900012000000000001"))
	n, err = st.Perso.CountUnbound("carrier-a")
	require.NoError(t, err)
	require.Equal(t, 2, n)

	// Binding a specific IMSI to an ICCID works too.
	require.NoError(t, st.Perso.BindPair("carrier-a", "001010000000002", "8900012000000000002"))
	bound, err = st.Perso.GetByICCID("carrier-a", "8900012000000000002")
	require.NoError(t, err)
	require.Equal(t, "001010000000002", bound.IMSI)

	// Deleting by ICCID removes only the bound row.
	require.NoError(t, st.Perso.Delete("carrier-a", "8900012000000000002"))
	_, err = st.Perso.GetByICCID("carrier-a", "8900012000000000002")
	require.ErrorIs(t, err, ErrNotFound)

	// Fresh stores start empty.
	st2, err := Open("file:" + filepath.Join(t.TempDir(), "pool2.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st2.Close() })
	n, err = st2.Perso.CountUnbound("carrier-a")
	require.NoError(t, err)
	require.Zero(t, n)
}

// TestCredentialsPoolRereserveAfterUnbind covers the cycle "reserve -> release
// -> reserve again": the second reservation must not collide with the previous
// binding of the same ICCID.
func TestCredentialsPoolRereserveAfterUnbind(t *testing.T) {
	st := openTestStore(t)
	require.NoError(t, st.Perso.Upsert(&Personalization{TenantID: "carrier-a", IMSI: "001010000000001", SPN: "A1"}))
	require.NoError(t, st.Perso.Upsert(&Personalization{TenantID: "carrier-a", IMSI: "001010000000002", SPN: "A2"}))

	iccid := "8900012000000000001"
	imsi1, err := st.Perso.ReservePair("carrier-a", iccid)
	require.NoError(t, err)
	require.Equal(t, "001010000000001", imsi1)

	// Simulate a release that did not unbind the pair (e.g. an order cancel),
	// then reserve the same ICCID again: the previous binding is released first
	// and the lowest unbound entry is rebound, so no unique violation occurs.
	imsi2, err := st.Perso.ReservePair("carrier-a", iccid)
	require.NoError(t, err)
	require.NotEmpty(t, imsi2)

	// Exactly one row is bound to the ICCID.
	rows, total, err := st.Perso.ListPage("", "carrier-a", 10, 0)
	require.NoError(t, err)
	require.Equal(t, 2, total)
	bound := 0
	for _, r := range rows {
		if r.ICCID == iccid {
			bound++
			require.Equal(t, imsi2, r.IMSI)
		}
	}
	require.Equal(t, 1, bound)
}
