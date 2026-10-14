package api

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api/common"
	"rsp42/internal/api/middleware"
	"rsp42/internal/store"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// readBodyHandler reports the body size, or 413 when the router's budget
// rejected it.
func readBodyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := common.ReadRaw(w, r, 0)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strconv.Itoa(len(b))))
	}
}

// TestBodyLimitIsAuthoritative pins that api.Options.BodyLimit is the single
// place the request-body budget is configured: the handler carries no constant
// of its own, so the router's value (not a per-package default) decides.
func TestBodyLimitIsAuthoritative(t *testing.T) {
	cases := []struct {
		name  string
		opts  Options
		body  int
		want  int
		label string
	}{
		{"default rejects 2MiB", Options{}, 2 << 20, http.StatusRequestEntityTooLarge, "default budget"},
		{"explicit 4MiB accepts 2MiB", Options{BodyLimit: 4 << 20}, 2 << 20, http.StatusOK, "raised budget"},
		{"tiny budget rejects", Options{BodyLimit: 16}, 100, http.StatusRequestEntityTooLarge, "lowered budget"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base(testLogger(), tc.opts, "es2p")
			r.Post("/x", readBodyHandler())
			srv := httptest.NewServer(r)
			defer srv.Close()

			resp, err := http.Post(srv.URL+"/x", "application/json", bytes.NewReader(make([]byte, tc.body)))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, tc.want, resp.StatusCode, tc.label)
		})
	}
}

// TestIdempotencyUsesRouterBodyBudget pins that the idempotency replay buffer
// follows the router's budget instead of its own smaller constant: an admin
// upload larger than the protocol default must reach the handler intact.
func TestIdempotencyUsesRouterBodyBudget(t *testing.T) {
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "idem.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	const size = 2 << 20
	got := -1
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, rerr := common.ReadRaw(w, r, 0)
		require.NoError(t, rerr)
		got = len(b)
		w.WriteHeader(http.StatusOK)
	})

	r := base(testLogger(), Options{BodyLimit: 4 << 20}, "admin")
	r.With(middleware.Idempotency(st.Idem)).Post("/x", h)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/x", bytes.NewReader(make([]byte, size)))
	require.NoError(t, err)
	req.Header.Set("Idempotency-Key", "k1")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, size, got, "the idempotency buffer must not truncate an admin upload")
}
