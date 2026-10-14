package es2plus_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api"
	"rsp42/internal/api/es12"
	"rsp42/internal/api/es2plus"
	"rsp42/internal/client/es2p"
	"rsp42/internal/iccid"
	"rsp42/internal/service"
	"rsp42/internal/store"
	"rsp42/internal/testutil/mockoperator"
	"time"
)

func newServer(t *testing.T) (*es2p.Client, *store.Store) {
	t.Helper()
	return newServerWith(t, nil)
}

// newServerWith builds an ES2+ test server; configure may adjust the handler
// (e.g. install a tenant mapping or the idempotency repository).
func newServerWith(t *testing.T, configure func(h *es2plus.Handler, st *store.Store)) (*es2p.Client, *store.Store) {
	t.Helper()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "es2p.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	orders := service.NewOrderService(st.Profiles)
	inventory := service.NewInventory(st.Profiles, "8900012", "00101")
	inventory.Pool = st.Pool
	h := es2plus.New(slog.Default(), st.Profiles, orders, inventory)
	h.OrderAudit = st.Orders
	if configure != nil {
		configure(h, st)
	}

	// ES12 server (Root SM-DS) + registrar so ConfirmOrder registers events.
	events := service.NewEventService(st.Events, "root", "testrootsmds.example.com", time.Hour)
	es12srv := httptest.NewServer(api.NewES12Router(slog.Default(), es12.New(slog.Default(), events), api.Options{}))
	t.Cleanup(es12srv.Close)
	h.Registrar = &service.Registrar{
		Repo:        st.Regs,
		Client:      service.NewSMDSCClient(es12srv.URL, "2.999.10", nil),
		SMDPAddress: "testsmdpplus1.example.com",
		Forwarding:  true,
	}

	srv := httptest.NewServer(api.NewES2PRouter(slog.Default(), h, api.Options{}))
	t.Cleanup(srv.Close)
	return es2p.NewClient(srv.URL, "test-operator", nil), st
}

func TestES2PlusOrderFlow(t *testing.T) {
	client, st := newServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrder(ctx, "89049032123451234512345678901235", "", "operational")
	require.NoError(t, err)
	require.Len(t, dl.ICCID, 19)

	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateLinked, p.State)
	require.Equal(t, "89049032123451234512345678901235", p.EID)

	co, err := client.ConfirmOrder(ctx, es2p.ConfirmOrderRequest{
		ICCID:            dl.ICCID,
		ConfirmationCode: "1234",
		ReleaseFlag:      true,
	})
	require.NoError(t, err)
	require.NotEmpty(t, co.MatchingID)

	p, err = st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, p.State)
	require.True(t, p.CCRequired)
	require.NotEmpty(t, p.CCHash)

	// ReleaseProfile is idempotent on an already released profile.
	require.NoError(t, client.ReleaseProfile(ctx, dl.ICCID))

	// Order audit rows were written.
	var orderCount int
	require.NoError(t, st.DB.QueryRow("SELECT COUNT(*) FROM orders").Scan(&orderCount))
	require.GreaterOrEqual(t, orderCount, 2)
}

func TestConfirmOrderRegistersEvent(t *testing.T) {
	client, st := newServer(t)
	ctx := context.Background()

	eid := "89049032123451234512345678901235"
	dl, err := client.DownloadOrder(ctx, eid, "", "operational")
	require.NoError(t, err)
	co, err := client.ConfirmOrder(ctx, es2p.ConfirmOrderRequest{
		ICCID: dl.ICCID, SMDSAddress: "testrootsmds.example.com",
	})
	require.NoError(t, err)

	// The event was registered at the (mock) Root SM-DS with eventId == matchingId.
	recs, err := st.Events.ListByEID(eid)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	require.Equal(t, co.MatchingID, recs[0].EventID)

	// The SM-DP+ recorded the registration for later deletion.
	regs, err := st.Regs.ListActiveByEID(eid)
	require.NoError(t, err)
	require.Len(t, regs, 1)
}

func TestES2PlusCancelOrder(t *testing.T) {
	client, st := newServer(t)
	ctx := context.Background()

	dl, err := client.DownloadOrder(ctx, "", "", "operational")
	require.NoError(t, err)
	require.NoError(t, client.CancelOrder(ctx, dl.ICCID, "", "", "unavailable"))
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateUnavailable, p.State)
}

func TestMockOperatorCallback(t *testing.T) {
	op := mockoperator.NewOperator()
	srv := httptest.NewServer(op.Handler())
	defer srv.Close()

	st := newCallbackStore(t)
	cb := es2p.NewCallbackClient(srv.URL+"/gsma/rsp2/es2plus/handleDownloadProgressInfo", "smdpp", nil)
	q := es2p.NewCallbackQueue(st.Callbacks, cb, slog.Default())

	err := q.Deliver(context.Background(), service.ProgressInfo{
		ICCID:                   "8900012345678901234F",
		NotificationPointID:     es2p.NotificationPointDownload,
		NotificationPointStatus: service.PointStatus{Status: "Executed-Success"},
	})
	require.NoError(t, err)
	require.Equal(t, 1, op.ProgressCount())

	// The wire contract is the documented payload: field names, presence
	// (profileType always present, resultData/eid omitted when empty) and the
	// nested notificationPointStatus object.
	var body map[string]any
	require.NoError(t, json.Unmarshal(op.Progress[0], &body))
	require.Equal(t, "8900012345678901234F", body["iccid"])
	require.EqualValues(t, es2p.NotificationPointDownload, body["notificationPointId"])
	require.Equal(t, map[string]any{"status": "Executed-Success"}, body["notificationPointStatus"])
	require.Contains(t, body, "profileType")
	require.NotContains(t, body, "resultData")
	require.NotContains(t, body, "eid")
	header, ok := body["header"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "smdpp", header["functionRequesterIdentifier"])
}

// luhnICCID appends the Luhn check digit for an 18-digit body.
func luhnICCID(t *testing.T, body string) string {
	t.Helper()
	check, err := iccid.LuhnCheckDigit(body)
	require.NoError(t, err)
	return body + string(rune('0'+check))
}

func TestDownloadOrderWithRequestedICCID(t *testing.T) {
	client, st := newServer(t)
	iccid := luhnICCID(t, "890001234567890123")

	dl, err := client.DownloadOrder(context.Background(), "", iccid, "operational")
	require.NoError(t, err)
	require.Equal(t, iccid, dl.ICCID)

	p, err := st.Profiles.GetByICCID(iccid)
	require.NoError(t, err)
	require.Equal(t, store.StateAllocated, p.State)
}

func TestDownloadOrderRequestedICCIDResend(t *testing.T) {
	client, st := newServer(t)
	iccid := luhnICCID(t, "890001234567890123")

	first, err := client.DownloadOrder(context.Background(), "", iccid, "operational")
	require.NoError(t, err)
	require.Equal(t, iccid, first.ICCID)

	// SGP.22 Table 24 NOTE: an identical resend (same ICCID, same profileType,
	// same EID, still Allocated/Linked) answers Executed-Success and creates no
	// second profile.
	second, err := client.DownloadOrder(context.Background(), "", iccid, "operational")
	require.NoError(t, err)
	require.Equal(t, iccid, second.ICCID)
	_, total, err := st.Profiles.ListFiltered(store.ProfileFilter{ICCID: iccid}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 1, total)

	// A different profileType is not the same result: it must be refused.
	_, err = client.DownloadOrder(context.Background(), "", iccid, "other")
	require.Error(t, err)
}

func TestDownloadOrderRequestedICCIDInvalid(t *testing.T) {
	client, _ := newServer(t)
	ctx := context.Background()

	// Wrong length.
	_, err := client.DownloadOrder(ctx, "", "12345", "operational")
	require.Error(t, err)

	// Bad Luhn check digit.
	body := "890001234567890123"
	check, err := iccid.LuhnCheckDigit(body)
	require.NoError(t, err)
	bad := body + string(rune('0'+(check+1)%10))
	_, err = client.DownloadOrder(ctx, "", bad, "operational")
	require.Error(t, err)
}

func TestCancelOrderFinalStatus(t *testing.T) {
	client, st := newServer(t)
	dl, err := client.DownloadOrder(context.Background(), "", "", "operational")
	require.NoError(t, err)

	// The value is matched case-insensitively.
	require.NoError(t, client.CancelOrder(context.Background(), dl.ICCID, "", "", "unavailable"))
	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateUnavailable, p.State)
}

func TestCancelOrderRejectsInvalidFinalStatus(t *testing.T) {
	client, st := newServer(t)
	dl, err := client.DownloadOrder(context.Background(), "", "", "operational")
	require.NoError(t, err)

	// Table 29 defines only Available/Unavailable; anything else is refused.
	require.Error(t, client.CancelOrder(context.Background(), dl.ICCID, "", "", "1"))
	require.Error(t, client.CancelOrder(context.Background(), dl.ICCID, "", "", "bogus"))

	p, err := st.Profiles.GetByICCID(dl.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateAllocated, p.State)
}
