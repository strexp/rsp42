package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistryRender(t *testing.T) {
	reg := NewRegistry()
	reg.Describe("rsp42_downloads_total", Counter, "Downloads by tenant.")
	reg.Describe("rsp42_pool", Gauge, "Pool entries by state.")

	reg.Inc("rsp42_downloads_total", map[string]string{"tenant": "carrier-a"})
	reg.Add("rsp42_downloads_total", map[string]string{"tenant": "carrier-a"}, 2)
	reg.Inc("rsp42_downloads_total", map[string]string{"tenant": "carrier-b"})
	reg.Set("rsp42_pool", map[string]string{"state": "available"}, 7)

	out := reg.Render()
	require.Contains(t, out, "# TYPE rsp42_downloads_total counter")
	require.Contains(t, out, "# HELP rsp42_pool Pool entries by state.")
	require.Contains(t, out, `rsp42_downloads_total{tenant="carrier-a"} 3`)
	require.Contains(t, out, `rsp42_downloads_total{tenant="carrier-b"} 1`)
	require.Contains(t, out, `rsp42_pool{state="available"} 7`)

	// Metrics are emitted in declaration order and unlabelled series render bare.
	require.Less(t, strings.Index(out, "rsp42_downloads_total"), strings.Index(out, "rsp42_pool"))
	reg.Set("rsp42_pool", nil, 1)
	require.Contains(t, reg.Render(), "rsp42_pool 1")
}

func TestHandlerRunsCollectors(t *testing.T) {
	reg := NewRegistry()
	calls := 0
	h := Handler(reg, func(r *Registry) {
		calls++
		r.Set("rsp42_collected", nil, 42)
	})

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	require.Equal(t, 200, rec.Code)
	require.Equal(t, 1, calls)
	require.Contains(t, rec.Body.String(), "rsp42_collected 42")
	require.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
}
