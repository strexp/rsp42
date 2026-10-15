package es2plus_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api"
	"rsp42/internal/api/es2plus"
	"rsp42/internal/audit"
	"rsp42/internal/client/es12"
	"rsp42/internal/client/es2p"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

const testEID = "89049032123451234512345678901235"

// TestProfileTypePlatformDefaultSelector covers F5: the empty tenant part of the
// "<tenant>/<template>" selector names a template owned by the platform-default
// tenant (a global template, e.g. one promoted with POST /upp/{name}/promote).
// Without it there is no way for a mapped caller to select such a template.
func TestProfileTypePlatformDefaultSelector(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()
	require.NoError(t, st.UPP.Upsert(&store.UPPTemplate{
		Name: "tpl-global", SAIPMajor: 2, SAIPMinor: 1, SHA256: "g", Bytes: []byte{1}, Active: true,
	}))

	// A tenant caller reaches the global template through the empty prefix.
	dl, err := client.DownloadOrderWith(ctx, "", "", "/tpl-global", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, "tpl-global", p.UPPTemplate)
	require.Equal(t, "carrier-a", p.TenantID)

	var se *es2p.StatusError
	// A selector with no template name is still malformed.
	_, err = client.DownloadOrderWith(ctx, "", "", "/", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.5", "3.9"), "got %v", err)

	// A named other tenant is still an authorisation failure.
	_, err = client.DownloadOrderWith(ctx, "", "", "carrier-b/tpl-b", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.5", "1.2"), "got %v", err)
}

// TestCancelOrderStandardVerifications covers F4: the verifications of §5.3.3,
// with the status codes of Table 30.
func TestCancelOrderStandardVerifications(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()
	var se *es2p.StatusError

	// A Profile that is already downloaded may not be cancelled: 8.2.1/3.3.
	dl, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	p.State = store.StateDownloaded
	require.NoError(t, st.Profiles.Update(p))
	err = client.CancelOrderWith(ctx, dl.ICCID, testEID, "", "Available", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.3"), "already downloaded: got %v", err)

	// A pending order with a registered SM-DS event.
	dl2, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{
		ICCID: dl2.ICCID, EID: testEID, MatchingID: "M-CANCEL",
		SMDSAddress: "testrootsmds.example.com",
	}, es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	regs, err := st.Regs.ListActiveByEID(testEID)
	require.NoError(t, err)
	require.NotEmpty(t, regs, "confirmOrder with smdsAddress must register the event")

	// A different MatchingID is 8.2.6/3.10.
	err = client.CancelOrderWith(ctx, dl2.ICCID, testEID, "M-OTHER", "Available", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.6", "3.10"), "matchingId mismatch: got %v", err)

	// A different EID is 8.2.1/3.10.
	err = client.CancelOrderWith(ctx, dl2.ICCID, "89049032123451234512345678901299", "M-CANCEL", "Available", es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.1", "3.10"), "eid mismatch: got %v", err)

	// The matching values succeed, the ICCID returns to inventory, and §5.3.3's
	// event deletion runs.
	require.NoError(t, client.CancelOrderWith(ctx, dl2.ICCID, testEID, "M-CANCEL", "Available", es2p.CallOptions{Requester: "op-a"}))
	p2, err := st.Profiles.GetByICCID(dl2.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateAvailable, p2.State)
	regs, err = st.Regs.ListActiveByEID(testEID)
	require.NoError(t, err)
	require.Empty(t, regs, "a cancelled order must drop its SM-DS event registration")

	// Unavailable keeps the ICCID out of inventory.
	dl3, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	require.NoError(t, client.CancelOrderWith(ctx, dl3.ICCID, "", "", "Unavailable", es2p.CallOptions{Requester: "op-a"}))
	p3, err := st.Profiles.GetByICCID(dl3.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateUnavailable, p3.State)
}

// TestConfirmOrderStandardVerifications covers F6 (and Table 27's EID rule): a
// conflicting MatchingID is 8.2.6/3.3 and never leaks the store error, a
// malformed MatchingID is a malformed request, and an SM-DS registration needs
// the EID it is keyed by.
func TestConfirmOrderStandardVerifications(t *testing.T) {
	client, _ := newTenantServer(t)
	ctx := context.Background()
	var se *es2p.StatusError

	// §4.1.1: only upper case alphanumeric characters and '-' are allowed.
	dl, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl.ICCID, MatchingID: "lower-case"}, es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.1", "1.2"), "malformed matchingId: got %v", err)

	// Two orders may not share a MatchingID (Table 27 8.2.6/3.3). The store's
	// unique index decides, and its error text must not reach the caller.
	dl2, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl2.ICCID, MatchingID: "M-DUP"}, es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)

	dl3, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{ICCID: dl3.ICCID, MatchingID: "M-DUP"}, es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.2.6", "3.3"), "conflicting matchingId: got %v", err)
	require.NotContains(t, err.Error(), "UNIQUE")
	require.NotContains(t, err.Error(), "constraint")
	require.NotContains(t, err.Error(), "store:")

	// Table 27: an SM-DS address makes the EID mandatory (the event is keyed by
	// it), so an anonymous order cannot request one.
	dl4, err := client.DownloadOrderWith(ctx, "", "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)
	_, err = client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{
		ICCID: dl4.ICCID, SMDSAddress: "testrootsmds.example.com",
	}, es2p.CallOptions{Requester: "op-a"})
	require.ErrorAs(t, err, &se)
	require.True(t, se.IsCode("8.1.1", "2.2"), "eid missing with smdsAddress: got %v", err)
}

// TestConfirmOrderMatchingIDChangeDropsStaleEvent covers F8: the SM-DS
// registration is keyed by the MatchingID, so re-confirming an order with a
// different one must drop the previous registration rather than leave both.
func TestConfirmOrderMatchingIDChangeDropsStaleEvent(t *testing.T) {
	client, st := newTenantServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrderWith(ctx, testEID, "", "carrier-a/tpl-a", es2p.CallOptions{Requester: "op-a"})
	require.NoError(t, err)

	confirm := func(matchingID string) {
		t.Helper()
		_, err := client.ConfirmOrderWith(ctx, es2p.ConfirmOrderRequest{
			ICCID: dl.ICCID, EID: testEID, MatchingID: matchingID,
			SMDSAddress: "testrootsmds.example.com",
		}, es2p.CallOptions{Requester: "op-a"})
		require.NoError(t, err)
	}
	active := func() []string {
		t.Helper()
		regs, err := st.Regs.ListActiveByEID(testEID)
		require.NoError(t, err)
		out := make([]string, 0, len(regs))
		for _, g := range regs {
			out = append(out, g.EventID)
		}
		return out
	}

	confirm("M-OLD-1")
	require.Equal(t, []string{"M-OLD-1"}, active())

	confirm("M-NEW-2")
	require.Equal(t, []string{"M-NEW-2"}, active(), "the previous registration must be dropped")

	// A resend with the same MatchingID takes no other action.
	confirm("M-NEW-2")
	require.Equal(t, []string{"M-NEW-2"}, active())
}

// TestES12RegistrationFailureIsRecorded pins that the Registrar itself makes a
// failed registration observable, so every caller (ConfirmOrder, CancelOrder,
// the ACR-0 rotation, the install-time deletion) is covered by one code path
// rather than each repeating the metric and the audit row.
func TestES12RegistrationFailureIsRecorded(t *testing.T) {
	st := newCallbackStore(t)
	reg := newES2PMetricsRegistry()
	r := &service.Registrar{
		Repo: st.Regs,
		// Nothing listens here: the registration must fail.
		Client:      es12.NewSMDSCClient("http://127.0.0.1:1", "2.999.10", nil),
		SMDPAddress: "testsmdpplus1.example.com",
		Metrics:     reg,
		Audit:       st.Audit,
	}
	err := r.Register(testEID, "M-FAIL", "testrootsmds.example.com",
		es12.EventMeta{Tenant: "carrier-a", ICCID: "8900012345678901234"})
	require.Error(t, err)

	require.Contains(t, reg.Render(), `rsp42_es12_register_failures_total{tenant="carrier-a"} 1`)

	rows, err := st.Audit.List(10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "es12", rows[0].Interface)
	require.Equal(t, "registerEvent", rows[0].Function)
	require.Equal(t, "Failed", rows[0].Outcome)
	require.Equal(t, testEID, rows[0].Subject)
}

// TestUnmappedRequesterSignals covers F1: the platform-default fallback of an
// unmapped functionRequesterIdentifier is counted and lands on the audit row, so
// an operator health check has a signal (docs/interfaces.md).
func TestUnmappedRequesterSignals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	sink, err := audit.New(nil, "file", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sink.Close() })

	reg := newES2PMetricsRegistry()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "unmapped.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	inv := service.NewInventory(st.Profiles, "8900012", "00101")
	inv.Pool = st.Pool
	h := es2plus.New(es2plus.Deps{
		Log: log, Profiles: st.Profiles, Orders: service.NewOrderService(st.Profiles),
		Inventory: inv, OrderAudit: st.Orders, FQDN: "testsmdpplus1.example.com",
	})
	// One mapping exists, so an unmapped requester is a real attribution miss.
	h.RequesterTenants = service.NewTenantResolver([]service.RequesterTenant{
		{Requester: "op-a", Tenant: "carrier-a"},
	})
	h.Metrics = reg

	srv := httptest.NewServer(api.NewES2PRouter(log, h, api.Options{Audit: sink}))
	t.Cleanup(srv.Close)

	client := es2p.NewClient(srv.URL, "test-operator", nil)
	_, err = client.DownloadOrderWith(context.Background(), "", "", "", es2p.CallOptions{Requester: "op-never-registered"})
	require.NoError(t, err)

	require.Contains(t, reg.Render(), "rsp42_es2p_tenant_unmapped_total 1")

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var row struct {
		Function string         `json:"function"`
		TenantID string         `json:"tenantId"`
		Detail   map[string]any `json:"detail"`
	}
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(raw), &row))
	require.Equal(t, "downloadOrder", row.Function)
	require.Empty(t, row.TenantID, "an unmapped caller falls back to the platform-default tenant")
	require.Equal(t, "unmapped", row.Detail["warning"])
	require.Equal(t, "op-never-registered", row.Detail["requester"])
}
