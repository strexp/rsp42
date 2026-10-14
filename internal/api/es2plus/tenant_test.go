package es2plus_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api/es2plus"
	"rsp42/internal/client/es2p"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// newTenantServer returns a server with op-a -> carrier-a and op-b -> carrier-b,
// plus idempotency enabled and two tenant templates registered.
func newTenantServer(t *testing.T) (*es2p.Client, *store.Store) {
	t.Helper()
	client, st := newServerWith(t, func(h *es2plus.Handler, st *store.Store) {
		h.RequesterTenants = service.NewTenantResolver([]service.RequesterTenant{
			{Requester: "op-a", Tenant: "carrier-a"},
			{Requester: "op-b", Tenant: "carrier-b"},
		})
		h.UPP = st.UPP
		h.Idem = st.Idem
	})
	require.NoError(t, st.UPP.Upsert(&store.UPPTemplate{
		Name: "tpl-a", TenantID: "carrier-a", SAIPMajor: 2, SAIPMinor: 1,
		SHA256: "a", Bytes: []byte{1}, Active: true,
	}))
	require.NoError(t, st.UPP.Upsert(&store.UPPTemplate{
		Name: "tpl-b", TenantID: "carrier-b", SAIPMajor: 2, SAIPMinor: 1,
		SHA256: "b", Bytes: []byte{1}, Active: true,
	}))
	return client, st
}

func TestES2PlusTenantIsolation(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	dlA, err := client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	p, err := st.Profiles.GetByICCID(dlA.ICCID)
	require.NoError(t, err)
	require.Equal(t, "carrier-a", p.TenantID)

	dlB, err := client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{Requester: "op-b"})
	require.NoError(t, err)
	pB, err := st.Profiles.GetByICCID(dlB.ICCID)
	require.NoError(t, err)
	require.Equal(t, "carrier-b", pB.TenantID)

	// op-b may not touch carrier-a's profile: 8.2.1/1.2.
	err = client.CancelOrderWith(ctx, dlA.ICCID, "", "", "Available", es2p.CallOptions{Requester: "op-b"})
	var se *es2p.StatusError
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "1.2"), "got %v", err)

	err = client.ReleaseProfileWith(ctx, dlA.ICCID, es2p.CallOptions{Requester: "op-b"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "1.2"), "got %v", err)

	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dlA.ICCID}, es2p.CallOptions{Requester: "op-b"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "1.2"), "got %v", err)

	// The owning operator still can.
	require.NoError(t, client.CancelOrderWith(ctx, dlA.ICCID, "", "", "Available", es2p.CallOptions{Requester: "op-a"}))
}

func TestES2PlusProfileTypeSelectionAndAuthorisation(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	// "<tenant>/<template>" pins the tenant template on the order.
	dl, err := client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, "tpl-a", p.UPPTemplate)
	require.Equal(t, "carrier-a/tpl-a", p.ProfileType)

	// Selecting another tenant's template is an authorisation failure: 8.2.5/1.2.
	_, err = client.DownloadOrderWith(ctx, "", "", "carrier-b/tpl-b", es2p.CallOptions{Requester: "op-a"})
	var se *es2p.StatusError
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.5", "1.2"), "got %v", err)

	// An unknown template in the caller's own tenant: 8.2.5/3.9.
	_, err = client.DownloadOrderWith(ctx, "", "", "carrier-a/nope", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.5", "3.9"), "got %v", err)

	// A plain opaque profileType keeps working.
	_, err = client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
}

func TestConfirmOrderEIDConsistency(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	eid := "89049032123451234512345678901235"
	dl, err := client.DownloadOrderWith(ctx, eid, "", "operational", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)

	// A different EID must be refused with 8.1.1/3.10 Invalid Association.
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{
		ICCID: dl.ICCID, EID: "89049032123451234512345678901299",
	}, es2p.CallOptions{Requester: "op-a"})
	var se *es2p.StatusError
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.1.1", "3.10"), "got %v", err)
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, eid, p.EID)

	// The matching EID is accepted.
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl.ICCID, EID: eid}, es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
}

func TestES2PlusDistinguishableFailureCodes(t *testing.T) {
	client, _ := newTenantServer(t)
	ctx := context.Background()

	// Missing mandatory element: 8.1.1/2.2.
	_, err := client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{}, es2p.CallOptions{Requester: "op-a"})
	var se *es2p.StatusError
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.1.1", "2.2"), "got %v", err)

	// Unknown ICCID: 8.2.1/3.9 (not 8.2.5/3.9, which means Profile Type unknown).
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: "8900012345678901234"}, es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.9"), "got %v", err)

	err = client.ReleaseProfileWith(ctx, "8900012345678901234", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.9"), "got %v", err)

	// CancelOrder rejects an unknown finalProfileStatusIndicator with 8.2.1/1.2.
	dl, err := client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	err = client.CancelOrderWith(ctx, dl.ICCID, "", "", "bogus", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "1.2"), "got %v", err)
}

func TestES2PlusIdempotencyKeyReplay(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)

	opts := es2p.CallOptions{Requester: "op-a", IdempotencyKey: "confirm-1"}
	first, err := client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl.ICCID, MatchingID: "M-1"}, opts)
	require.NoError(t, err)
	require.Equal(t, "M-1", first.MatchingID)

	// The replay returns the recorded response and repeats no side effect.
	second, err := client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl.ICCID, MatchingID: "M-1"}, opts)
	require.NoError(t, err)
	require.Equal(t, first.MatchingID, second.MatchingID)

	var confirmRows int
	require.NoError(t, st.DB.QueryRow(`SELECT COUNT(*) FROM orders WHERE action = 'confirmOrder'`).Scan(&confirmRows))
	require.Equal(t, 1, confirmRows)

	// The same key with a different body is an HTTP 409 conflict.
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl.ICCID, MatchingID: "M-2"}, opts)
	require.Error(t, err)
	var he *es2p.HTTPError
	require.ErrorAs(t, err, &he)
	require.Equal(t, http.StatusConflict, he.StatusCode)
	require.Contains(t, he.Body, "idempotency_key_reused")
}

func TestES2PlusUnmappedRequesterUsesPlatformDefault(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{Requester: "unknown-op"})
	require.NoError(t, err)
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Empty(t, p.TenantID)
}

// TestES2PlusAllocationErrorCodes pins C3: quota exhaustion and an unusable
// ICCID are distinguishable from a generic allocation failure.
func TestES2PlusAllocationErrorCodes(t *testing.T) {
	ctx := context.Background()

	// Quota exhausted (limit 0) -> 8.2.5/3.7 No more Profile available.
	client, _ := newServerWith(t, func(h *es2plus.Handler, st *store.Store) {
		zero := 0
		h.Inventory.ProfileQuota = func(tenant string) (*int, error) { return &zero, nil }
		h.Inventory.CountProfiles = func(tenant string) (int, error) { return 0, nil }
	})
	_, err := client.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{})
	var se *es2p.StatusError
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.5", "3.7"), "got %v", err)

	// An ICCID that is already in use -> 8.2.1/3.3 Already in Use.
	client2, st2 := newServerWith(t, nil)
	first, err := client2.DownloadOrderWith(ctx, "", "", "operational", es2p.CallOptions{})
	require.NoError(t, err)
	_, err = client2.DownloadOrderWith(ctx, "", first.ICCID, "other", es2p.CallOptions{})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.3"), "got %v", err)
	_ = st2
}

// TestES2PlusUnparsedProfileTypeAudited pins C2: an opaque profileType is
// recorded instead of silently falling back to the version-selected template.
func TestES2PlusUnparsedProfileTypeAudited(t *testing.T) {
	client, st := newServerWith(t, func(h *es2plus.Handler, st *store.Store) {
		h.AuditRepo = st.Audit
	})
	dl, err := client.DownloadOrderWith(context.Background(), "", "", "operational", es2p.CallOptions{})
	require.NoError(t, err)

	entries, err := st.Audit.ListBySubject(dl.ICCID, 10)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	require.Equal(t, "downloadOrder", entries[0].Function)
	require.Contains(t, entries[0].DetailJSON, "profileType-unparsed")
}
