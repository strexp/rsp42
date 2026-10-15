package es2plus_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/client/es2p"
	"rsp42/internal/store"
)

// importRangeFor imports a block of ICCIDs for one tenant and returns the first
// available entry. Non-Luhn values inside the block are skipped by the importer,
// so the test never hardcodes a check digit.
func importRangeFor(t *testing.T, st *store.Store, tenant string) string {
	t.Helper()
	_, inserted, _, err := st.Pool.ImportRange(tenant, "89000123456789012340", "89000123456789012359", "")
	require.NoError(t, err)
	require.NotZero(t, inserted)
	entries, _, err := st.Pool.ListPage("available", "", &tenant, 1, 0)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	return entries[0].ICCID
}

// TestDownloadOrderRejectsForeignPooledICCID is Q7: an ICCID that is available
// in another tenant's pool may not be taken by naming it. Before the fix the
// explicit-ICCID path only checked the entry's blocked state, so the caller got
// Executed-Success and the original owner silently lost the ICCID.
func TestDownloadOrderRejectsForeignPooledICCID(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()
	iccidA := importRangeFor(t, st, "carrier-a")

	// op-b (carrier-b) names carrier-a's ICCID: 8.2.1/3.3, as A23 expects.
	var se *es2p.StatusError
	_, err := client.DownloadOrderWith(ctx, "", iccidA, "carrier-b/tpl-b", es2p.CallOptions{Requester: "op-b"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.3"), "got %v", err)

	// The entry keeps its owner and is not bound to a Profile.
	entry, err := st.Pool.Get(iccidA)
	require.NoError(t, err)
	require.Equal(t, "carrier-a", entry.TenantID)
	require.Equal(t, "available", entry.State)
	require.Nil(t, entry.ProfileID)
	_, err = st.Profiles.GetByICCID(iccidA)
	require.ErrorIs(t, err, store.ErrNotFound, "no Profile may be created for the refused ICCID")

	// The owner may still take it.
	dl, err := client.DownloadOrderWith(ctx, "", iccidA, "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.Equal(t, iccidA, dl.ICCID)
}

// TestDownloadOrderReusesCancelledICCID is Q1: cancelOrder with
// finalProfileStatusIndicator=Available puts the Profile back in Available,
// which SGP.22 Table 29 defines as "available for future use". A later
// DownloadOrder naming that ICCID must re-issue the same Profile row.
func TestDownloadOrderReusesCancelledICCID(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	first, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateLinked, first.State)

	require.NoError(t, client.CancelOrderWith(ctx, dl.ICCID, testEID, "", "Available", es2p.CallOptions{Requester: "op-a"}))
	cancelled, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateAvailable, cancelled.State)

	again, err := client.DownloadOrderWith(ctx, testEID, dl.ICCID, "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.Equal(t, dl.ICCID, again.ICCID)

	reused, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, first.ID, reused.ID, "the same Profile row is re-issued")
	require.Equal(t, store.StateLinked, reused.State)
	require.Equal(t, testEID, reused.EID)
	require.Empty(t, reused.MatchingID, "the cancelled order's MatchingID must not leak")
	require.Zero(t, reused.DownloadAttempts)

	// The same ICCID may be re-issued without an EID: the order attributes
	// change, the Profile identity does not.
	require.NoError(t, client.CancelOrderWith(ctx, dl.ICCID, testEID, "", "Available", es2p.CallOptions{Requester: "op-a"}))
	again2, err := client.DownloadOrderWith(ctx, "", dl.ICCID, "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.Equal(t, dl.ICCID, again2.ICCID)
	plain, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateAllocated, plain.State)
	require.Empty(t, plain.EID)
	require.Equal(t, first.ID, plain.ID, "still the same row, only the order attributes change")
}

// TestDownloadOrderDoesNotReuseDownloadedProfile pins the guard on Q1: a Profile
// that was ever downloaded is not re-issued by a fresh DownloadOrder, even if an
// operator forced it back to Available. The sanctioned redownload path is
// Installed -> Released after a Delete Notification.
func TestDownloadOrderDoesNotReuseDownloadedProfile(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.NoError(t, client.CancelOrderWith(ctx, dl.ICCID, "", "", "Available", es2p.CallOptions{Requester: "op-a"}))

	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	p.DownloadAttempts = 1
	require.NoError(t, st.Profiles.Update(p))

	var se *es2p.StatusError
	_, err = client.DownloadOrderWith(ctx, "", dl.ICCID, "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.3"), "got %v", err)
}

// TestPooledAllocationReusesCancelledICCID mirrors Q1 on the pool path: a
// downloadOrder without an ICCID reserves the tenant's lowest available pooled
// ICCID, and when that ICCID's cancelled row is back in Available the row is
// re-issued instead of a second Profile being minted outside the pool.
func TestPooledAllocationReusesCancelledICCID(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()
	iccidA := importRangeFor(t, st, "carrier-a")

	first, err := client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.Equal(t, iccidA, first.ICCID, "the pool is the ICCID source")
	row, err := st.Profiles.GetByICCID(first.ICCID)
	require.NoError(t, err)

	require.NoError(t, client.CancelOrderWith(ctx, first.ICCID, "", "", "Available", es2p.CallOptions{Requester: "op-a"}))

	second, err := client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.Equal(t, first.ICCID, second.ICCID)
	again, err := st.Profiles.GetByICCID(second.ICCID)
	require.NoError(t, err)
	require.Equal(t, row.ID, again.ID, "the pooled ICCID keeps its Profile row")

	_, total, err := st.Profiles.ListFiltered(store.ProfileFilter{Tenant: ptr("carrier-a")}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 1, total, "no second Profile may be created")
}

// TestPooledAllocationDoesNotMintOutsideThePool pins the other half of Q1: when
// the pool offers an ICCID whose Profile is not reusable, the request fails with
// "no Profile available" instead of silently generating an ICCID the operator
// never imported.
func TestPooledAllocationDoesNotMintOutsideThePool(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()
	iccidA := importRangeFor(t, st, "carrier-a")

	first, err := client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)

	// A downloaded Profile whose ICCID an operator released back to the pool is
	// not re-issuable; the pool entry is stuck until the operator blocks it.
	p, err := st.Profiles.GetByICCID(first.ICCID)
	require.NoError(t, err)
	p.State = store.StateDownloaded
	require.NoError(t, st.Profiles.Update(p))
	require.NoError(t, st.Pool.SetState(first.ICCID, "available", ""))

	var se *es2p.StatusError
	_, err = client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.5", "3.7"), "got %v", err)

	_, total, err := st.Profiles.ListFiltered(store.ProfileFilter{Tenant: ptr("carrier-a")}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 1, total, "no ICCID may be minted outside the pool")

	// The reservation was handed back so the entry is not parked as allocated.
	entry, err := st.Pool.Get(iccidA)
	require.NoError(t, err)
	require.Equal(t, "available", entry.State)
	require.Nil(t, entry.ProfileID)
}

// TestConfirmOrderReturnsSMDPAddress is Q6: Table 26's optional smdpAddress is
// this deployment's own FQDN, so an operator that only talks ES2+ can build the
// Activation Code without out-of-band configuration.
func TestConfirmOrderReturnsSMDPAddress(t *testing.T) {
	client, _ := newTenantServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	res, err := client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{
		ICCID: dl.ICCID, EID: testEID, MatchingID: "M-SMDP",
	}, es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.Equal(t, "testsmdpplus1.example.com", res.SMDPAddress)
	require.Equal(t, "M-SMDP", res.MatchingID)
}

// ptr is the *string helper for the store filters used above.
func ptr[T any](v T) *T { return &v }
