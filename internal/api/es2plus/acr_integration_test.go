package es2plus_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/client/es2p"
	"rsp42/internal/mockoperator"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// TestACRCheckerAgainstMockOperator closes the G13 loop in one process: the
// SM-DP+ ACR hook (service.ACRChecker) driving the real ES2+ client against the
// test-only mock Operator. It asserts the operator is actually called, that a
// refusal is classified as a refusal, and that both outcomes are observable.
func TestACRCheckerAgainstMockOperator(t *testing.T) {
	operator := mockoperator.NewOperator()
	srv := httptest.NewServer(operator.Handler())
	t.Cleanup(srv.Close)

	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "acr.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	reg := newES2PMetricsRegistry()

	client := es2p.NewCallbackClient("", "2.999.10", nil)
	client.ACRURL = srv.URL + "/gsma/rsp2/es2plus/handleAcrRequest"
	checker := &service.ACRChecker{
		Operator: client,
		Timeout:  2 * time.Second,
		Metrics:  reg,
		Audit:    st.Audit,
	}
	profile := &store.Profile{ICCID: "89000123456789012341", TenantID: "carrier-a"}
	ctx := context.Background()

	// Allowed.
	require.NoError(t, checker.Check(ctx, profile))
	require.Equal(t, 1, operator.ACRCount())

	var sent struct {
		Header map[string]string `json:"header"`
		ICCID  string            `json:"iccid"`
	}
	require.NoError(t, json.Unmarshal(operator.ACRRequests[0], &sent))
	require.Equal(t, profile.ICCID, sent.ICCID)
	require.Equal(t, "2.999.10", sent.Header["functionRequesterIdentifier"])

	// Refused: the operator answers Failed (8.2.1/1.2).
	operator.RefuseACR = true
	err = checker.Check(ctx, profile)
	require.Error(t, err)
	require.ErrorIs(t, err, rsp.ErrACRRefused)
	require.Equal(t, 2, operator.ACRCount())

	// Both outcomes are recorded against the tenant.
	out := reg.Render()
	require.Contains(t, out, `outcome="allowed"`)
	require.Contains(t, out, `outcome="refused"`)
	require.Contains(t, out, `tenant="carrier-a"`)

	entries, err := st.Audit.ListBySubject(profile.ICCID, 10)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	statuses := map[string]string{}
	for _, e := range entries {
		statuses[e.Outcome] = e.StatusCode
		require.Equal(t, "es2p", e.Interface)
		require.Equal(t, "handleAcrRequest", e.Function)
		require.Equal(t, "carrier-a", e.TenantID)
	}
	require.Equal(t, "8.2.1/1.2", statuses["Failed"])
	require.Empty(t, statuses["Executed-Success"])
}

// TestACRCheckerTimeoutAgainstBlackholeOperator proves the timeout bound is
// real: an Operator that never answers cannot stall the confirmation.
func TestACRCheckerTimeoutAgainstBlackholeOperator(t *testing.T) {
	// The handler blocks until released. Cleanups run LIFO, so srv.Close is
	// registered first (it runs last) and the release second: the handler
	// always returns before Close waits on it.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	client := es2p.NewCallbackClient("", "2.999.10", nil)
	client.ACRURL = srv.URL
	client.MaxAttempts = 1
	checker := &service.ACRChecker{Operator: client, Timeout: 100 * time.Millisecond}

	start := time.Now()
	err := checker.Check(context.Background(), &store.Profile{ICCID: "89000123456789012341"})
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
}
