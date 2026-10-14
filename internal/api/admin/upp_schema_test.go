package admin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/service"
)

// fieldByName returns the annotated schema entry for a field.
func fieldByName(t *testing.T, fields []map[string]any, name string) map[string]any {
	t.Helper()
	for _, f := range fields {
		if f["name"] == name {
			return f
		}
	}
	t.Fatalf("field %q not found", name)
	return nil
}

// TestAdminUPPSchemaAvailability pins N4: the field catalog is resolved against
// the template, so the visual editor only offers bindable fields.
func TestAdminUPPSchemaAvailability(t *testing.T) {
	policy, err := service.NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)
	srv, _ := newTestServer(t, func(h *Handler) { h.AllowedSAIP = policy })
	base := srv.URL + "/admin/api/v1"

	data := uppFixture(t, "TS48v2_SAIP2.3_BERTLV.der")
	status, raw := do(t, "POST", base+"/upp", map[string]any{"name": "v23.der", "data": data})
	require.Equal(t, 200, status, string(raw))

	status, raw = do(t, "GET", base+"/upp/v23.der/schema", nil)
	require.Equal(t, 200, status, string(raw))
	var body struct {
		Fields []map[string]any `json:"fields"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	require.NotEmpty(t, body.Fields)

	iccid := fieldByName(t, body.Fields, "iccid")
	require.Equal(t, true, iccid["required"])
	require.Equal(t, true, iccid["applicable"])
	require.Equal(t, []any{"render"}, iccid["requiredIn"])
	require.NotEmpty(t, iccid["targets"])

	// The SAIP 2.3 profile carries PE-SecurityDomain and EF.AD (6FAD), so both
	// N17 fields are offered.
	sdKeys := fieldByName(t, body.Fields, "sdKeys")
	require.Equal(t, true, sdKeys["applicable"])
	require.Equal(t, []any{"securityDomain"}, sdKeys["targets"])

	mncLen := fieldByName(t, body.Fields, "mncLen")
	require.Equal(t, true, mncLen["applicable"])
	require.Equal(t, []any{"6FAD"}, mncLen["targets"])

	// Required is now derived from requiredIn; every field carries the keys.
	for _, f := range body.Fields {
		require.Contains(t, f, "applicable")
		require.Contains(t, f, "targets")
		require.Contains(t, f, "requiredIn")
		require.Equal(t, f["required"], containsFlow(f["requiredIn"], "render"), "field %v", f["name"])
	}
}

func containsFlow(v any, flow string) bool {
	list, _ := v.([]any)
	for _, x := range list {
		if s, _ := x.(string); s == flow {
			return true
		}
	}
	return false
}

// TestAdminRenderAdHocTemplate pins N5: /upp/render accepts an unregistered
// template as base64 DER (the upload wizard's "validate then preview" step) and
// rejects an ambiguous or empty request.
func TestAdminRenderAdHocTemplate(t *testing.T) {
	policy, err := service.NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)
	srv, _ := newTestServer(t, func(h *Handler) { h.AllowedSAIP = policy })
	base := srv.URL + "/admin/api/v1"

	data := uppFixture(t, "TS48v2_SAIP2.3_BERTLV.der")

	// Ad-hoc: no registry entry exists, yet the render succeeds.
	status, raw := do(t, "POST", base+"/upp/render", map[string]any{"data": data, "spn": "ADHOC"})
	require.Equal(t, 200, status, string(raw))
	var out struct {
		Rendered bool           `json:"rendered"`
		Error    string         `json:"error"`
		Template map[string]any `json:"template"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	require.True(t, out.Rendered, string(raw))
	require.Equal(t, "<ad-hoc>", out.Template["name"])

	// Nothing was stored.
	status, _ = do(t, "GET", base+"/upp/v23.der", nil)
	require.Equal(t, 404, status)

	// name and data together, or neither, are invalid requests.
	status, raw = do(t, "POST", base+"/upp/render", map[string]any{"name": "x", "data": data})
	require.Equal(t, 400, status, string(raw))
	require.Contains(t, string(raw), "invalid_request")

	status, raw = do(t, "POST", base+"/upp/render", map[string]any{"spn": "X"})
	require.Equal(t, 400, status, string(raw))
	require.Contains(t, string(raw), "invalid_request")
}

// TestAdminStatsAndSortContract pins N7's contract completion: the profile
// stats endpoint accepts groupBy=profile_type and the profile list accepts
// sort=tenant.
func TestAdminStatsAndSortContract(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	do(t, "POST", base+"/profiles", map[string]any{"tenant": "", "profileType": "operational"})
	do(t, "POST", base+"/profiles", map[string]any{"profileType": "test"})

	status, raw := do(t, "GET", base+"/profiles/stats?groupBy=profile_type", nil)
	require.Equal(t, 200, status, string(raw))
	require.Contains(t, string(raw), `"buckets"`)
	require.Contains(t, string(raw), `"groupBy":"profile_type"`)

	status, raw = do(t, "GET", base+"/profiles?sort=tenant", nil)
	require.Equal(t, 200, status, string(raw))
	require.Contains(t, string(raw), `"items"`)

	status, raw = do(t, "GET", base+"/profiles?sort=-tenant", nil)
	require.Equal(t, 200, status, string(raw))

	// An unsupported groupBy is still an invalid_request (stable code).
	status, raw = do(t, "GET", base+"/profiles/stats?groupBy=nonsense", nil)
	require.Equal(t, 400, status, string(raw))
	require.Contains(t, string(raw), `"code":"invalid_request"`)
}
