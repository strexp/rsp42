package es2plus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
)

// acrServer is a scriptable operator ACR endpoint.
type acrServer struct {
	calls   atomic.Int64
	bodies  []json.RawMessage
	handler func(w http.ResponseWriter, r *http.Request)
}

func (s *acrServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		s.bodies = append(s.bodies, raw)
		if s.handler != nil {
			s.handler(w, r)
			return
		}
		common.WriteJSON(w, common.NewSuccess())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newACRClient(url string) *CallbackClient {
	c := NewCallbackClient("", "2.999.10", nil)
	c.ACRURL = url
	c.Backoff = func(int) time.Duration { return 0 }
	return c
}

// TestHandleAcrRequestBodyIsSpecConformant pins the request shape: SGP.22
// §5.3.8 Table 32d / §6.5.2.20 define iccid as the only additional input data,
// so no private member may be added (docs/esim42-integration-gaps.md §8.2).
func TestHandleAcrRequestBodyIsSpecConformant(t *testing.T) {
	s := &acrServer{}
	srv := s.start(t)

	c := newACRClient(srv.URL)
	require.NoError(t, c.HandleAcrRequest(context.Background(), "89000123456789012341"))
	require.EqualValues(t, 1, s.calls.Load())
	require.Len(t, s.bodies, 1)

	var body map[string]any
	require.NoError(t, json.Unmarshal(s.bodies[0], &body))
	require.Equal(t, "89000123456789012341", body["iccid"])
	hdr, ok := body["header"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "2.999.10", hdr["functionRequesterIdentifier"])
	require.NotEmpty(t, hdr["functionCallIdentifier"])
	require.Len(t, body, 2, "the body must contain exactly header + iccid")
}

// TestHandleAcrRequestRefusalIsNotRetried mirrors SGP.22 §5.3.8: a Failed answer
// (8.2.1/1.2) is an Operator decision, so it must not be retried.
func TestHandleAcrRequestRefusalIsNotRetried(t *testing.T) {
	s := &acrServer{handler: func(w http.ResponseWriter, _ *http.Request) {
		common.WriteJSON(w, common.NewFailure(&common.StatusCodeData{
			SubjectCode: "8.2.1", ReasonCode: "1.2", Message: "Profile ICCID Not Allowed",
		}))
	}}
	srv := s.start(t)

	c := newACRClient(srv.URL)
	err := c.HandleAcrRequest(context.Background(), "89000123456789012341")
	require.Error(t, err)
	require.ErrorIs(t, err, rsp.ErrACRRefused)

	var refused *rsp.ACRRefusedError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, "8.2.1", refused.SubjectCode)
	require.Equal(t, "1.2", refused.ReasonCode)

	require.EqualValues(t, 1, s.calls.Load(), "a refusal must not be retried")
}

// TestHandleAcrRequestRetriesTransportFailures checks the retry policy: only
// transport/HTTP problems are retried, up to MaxAttempts.
func TestHandleAcrRequestRetriesTransportFailures(t *testing.T) {
	s := &acrServer{handler: func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}}
	srv := s.start(t)

	c := newACRClient(srv.URL)
	c.MaxAttempts = 4
	err := c.HandleAcrRequest(context.Background(), "89000123456789012341")
	require.Error(t, err)
	require.NotErrorIs(t, err, rsp.ErrACRRefused)
	require.EqualValues(t, 4, s.calls.Load())
}

// TestHandleAcrRequestRetriesThenSucceeds checks that a transient failure is
// recovered without surfacing an error.
func TestHandleAcrRequestRetriesThenSucceeds(t *testing.T) {
	s := &acrServer{}
	s.handler = func(w http.ResponseWriter, _ *http.Request) {
		if s.calls.Load() < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		s.handler = nil
		common.WriteJSON(w, common.NewSuccess())
	}
	srv := s.start(t)

	c := newACRClient(srv.URL)
	c.MaxAttempts = 3
	require.NoError(t, c.HandleAcrRequest(context.Background(), "89000123456789012341"))
	require.EqualValues(t, 2, s.calls.Load())
}

// TestHandleAcrRequestAcceptsWithWarning treats Executed-WithWarning as success,
// consistently with the rest of the ES2+ client.
func TestHandleAcrRequestAcceptsWithWarning(t *testing.T) {
	s := &acrServer{handler: func(w http.ResponseWriter, _ *http.Request) {
		common.WriteJSON(w, common.HeaderResponse{Header: common.ResponseHeader{
			FunctionExecutionStatus: common.FunctionExecutionStatus{
				Status:         common.StatusExecutedWithWarning,
				StatusCodeData: &common.StatusCodeData{SubjectCode: "8.2.1", ReasonCode: "1.2"},
			},
		}})
	}}
	srv := s.start(t)

	require.NoError(t, newACRClient(srv.URL).HandleAcrRequest(context.Background(), "89000123456789012341"))
}

// TestHandleAcrRequestWithoutURL is a configuration error, not a retry loop.
func TestHandleAcrRequestWithoutURL(t *testing.T) {
	c := NewCallbackClient("https://operator.example/cb", "2.999.10", nil)
	err := c.HandleAcrRequest(context.Background(), "89000123456789012341")
	require.ErrorIs(t, err, ErrACRNotConfigured)
}

// TestHandleAcrRequestHonoursContext checks that a cancelled request stops the
// retry loop instead of sleeping through the backoff.
func TestHandleAcrRequestHonoursContext(t *testing.T) {
	s := &acrServer{handler: func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}}
	srv := s.start(t)

	c := newACRClient(srv.URL)
	c.MaxAttempts = 5
	c.Backoff = func(int) time.Duration { return time.Hour }

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.HandleAcrRequest(ctx, "89000123456789012341")
	require.Error(t, err)
	require.Less(t, time.Since(start), 5*time.Second)
	require.EqualValues(t, 1, s.calls.Load())
}
