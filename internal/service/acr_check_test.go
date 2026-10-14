package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

type fakeACROperator struct {
	calls  int
	lastID string
	err    error
	block  time.Duration
	ctxErr error
}

func (f *fakeACROperator) HandleAcrRequest(ctx context.Context, iccid string) error {
	f.calls++
	f.lastID = iccid
	if f.block > 0 {
		select {
		case <-ctx.Done():
			f.ctxErr = ctx.Err()
			return ctx.Err()
		case <-time.After(f.block):
		}
	}
	return f.err
}

func newACRCheckerStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "acr.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestACRCheckerOutcomes(t *testing.T) {
	profile := &store.Profile{ICCID: "89000123456789012341", TenantID: "carrier-a"}

	cases := []struct {
		name        string
		err         error
		wantOutcome string
		wantAudit   string
		wantStatus  string
	}{
		{"allowed", nil, ACROutcomeAllowed, "Executed-Success", ""},
		{"refused", &rsp.ACRRefusedError{SubjectCode: "8.2.1", ReasonCode: "1.2", Message: "not allowed"}, ACROutcomeRefused, "Failed", "8.2.1/1.2"},
		{"transport error", errors.New("connection refused"), ACROutcomeError, "Failed", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newACRCheckerStore(t)
			reg := newServiceMetricsRegistry()
			op := &fakeACROperator{err: tc.err}
			c := &ACRChecker{Operator: op, Metrics: reg, Audit: st.Audit}

			err := c.Check(context.Background(), profile)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, 1, op.calls)
			require.Equal(t, profile.ICCID, op.lastID)

			// Metric carries the tenant and the classified outcome.
			out := reg.Render()
			require.Contains(t, out, `outcome="`+tc.wantOutcome+`"`)
			require.Contains(t, out, `tenant="carrier-a"`)

			// Audit row is attributed to the tenant and the ICCID.
			entries, err := st.Audit.ListBySubject(profile.ICCID, 10)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, "es2p", entries[0].Interface)
			require.Equal(t, "handleAcrRequest", entries[0].Function)
			require.Equal(t, tc.wantAudit, entries[0].Outcome)
			require.Equal(t, "carrier-a", entries[0].TenantID)
			require.Equal(t, tc.wantStatus, entries[0].StatusCode)
		})
	}
}

// TestACRCheckerRefusalIsRecognisedThroughWrapping matters because the client
// may wrap the refusal; classification must survive it.
func TestACRCheckerRefusalIsRecognisedThroughWrapping(t *testing.T) {
	st := newACRCheckerStore(t)
	reg := newServiceMetricsRegistry()
	refusal := &rsp.ACRRefusedError{SubjectCode: "8.2.1", ReasonCode: "1.2"}
	c := &ACRChecker{
		Operator: &fakeACROperator{err: errors.Join(errors.New("es2plus: wrapper"), refusal)},
		Metrics:  reg,
		Audit:    st.Audit,
	}
	require.Error(t, c.Check(context.Background(), &store.Profile{ICCID: "89000123456789012341"}))
	require.Contains(t, reg.Render(), `outcome="refused"`)
}

// TestACRCheckerTimeoutBoundsTheCall is the reason the checker exists: an
// unreachable Operator must not stall the LPA's authenticateClient.
func TestACRCheckerTimeoutBoundsTheCall(t *testing.T) {
	op := &fakeACROperator{block: time.Hour}
	c := &ACRChecker{Operator: op, Timeout: 50 * time.Millisecond}

	start := time.Now()
	err := c.Check(context.Background(), &store.Profile{ICCID: "89000123456789012341"})
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 5*time.Second)
	require.ErrorIs(t, op.ctxErr, context.DeadlineExceeded)
}

// TestACRCheckerHonoursCallerContext checks that the LPA's request context
// propagates to the outbound Operator call.
func TestACRCheckerHonoursCallerContext(t *testing.T) {
	op := &fakeACROperator{block: time.Hour}
	c := &ACRChecker{Operator: op}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, c.Check(ctx, &store.Profile{ICCID: "89000123456789012341"}), context.Canceled)
	require.Equal(t, 1, op.calls)
}

func TestACRCheckerRejectsMissingProfile(t *testing.T) {
	op := &fakeACROperator{}
	c := &ACRChecker{Operator: op}
	require.Error(t, c.Check(context.Background(), nil))
	require.Error(t, c.Check(context.Background(), &store.Profile{}))
	require.Zero(t, op.calls)

	// No operator configured is a wiring error, not an Operator refusal.
	require.Error(t, (&ACRChecker{}).Check(context.Background(), &store.Profile{ICCID: "89000123456789012341"}))
}
