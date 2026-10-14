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
	reg.Describe("rsp42_collected", Gauge, "Value produced by the collector.")
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

// TestUndeclaredMetricPanics pins that a typo fails loudly instead of creating
// an undeclared series with no type or help text.
func TestUndeclaredMetricPanics(t *testing.T) {
	reg := NewRegistry()
	require.PanicsWithValue(t, "metrics: undeclared metric rsp42_typo (call Describe first)", func() {
		reg.Inc("rsp42_typo", nil)
	})
	require.Panics(t, func() { reg.Set("rsp42_typo", nil, 1) })
}

// TestLabelValueEscaping pins the Prometheus escaping rules: only backslash,
// double quote and line feed are escaped. Go's %q would emit \x escapes (e.g.
// for a NUL byte), which Prometheus does not define.
func TestLabelValueEscaping(t *testing.T) {
	reg := NewRegistry()
	reg.Describe("rsp42_escaped_total", Counter, "Escaping.")

	reg.Inc("rsp42_escaped_total", map[string]string{"tenant": "a\"b"})
	out := reg.Render()
	require.Contains(t, out, `rsp42_escaped_total{tenant="a\"b"} 1`)

	reg.Inc("rsp42_escaped_total", map[string]string{"tenant": "back\\slash"})
	require.Contains(t, reg.Render(), `tenant="back\\slash"`)

	reg.Inc("rsp42_escaped_total", map[string]string{"tenant": "line\nfeed"})
	require.Contains(t, reg.Render(), `tenant="line\nfeed"`)

	// A NUL byte stays literal rather than becoming \x00.
	reg.Inc("rsp42_escaped_total", map[string]string{"tenant": "nul\x00byte"})
	require.Contains(t, reg.Render(), "tenant=\"nul\x00byte\"")
	require.NotContains(t, reg.Render(), `\x00`)
}
