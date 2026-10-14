package admin

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/service"
)

// uppFixture loads a non-UNIQUE testdata UPP fixture and returns it base64
// encoded, the form the management API accepts.
func uppFixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "upp", name))
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(raw)
}

// TestUPPVersionLimitAtBaseline pins N16: a template within the configured
// baseline is accepted and produces no version warning.
func TestUPPVersionLimitAtBaseline(t *testing.T) {
	policy, err := service.NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)
	srv, _ := newTestServer(t, func(h *Handler) { h.AllowedSAIP = policy })
	base := srv.URL + "/admin/api/v1"

	data := uppFixture(t, "TS48v2_SAIP2.3_BERTLV.der")
	status, raw := do(t, "POST", base+"/upp", map[string]any{"name": "v23.der", "data": data})
	require.Equal(t, 200, status, string(raw))

	status, raw = do(t, "POST", base+"/upp/validate", map[string]any{"data": data})
	require.Equal(t, 200, status, string(raw))
	var v struct {
		Valid    bool     `json:"valid"`
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.True(t, v.Valid)
	for _, w := range v.Warnings {
		require.NotContains(t, w, "supported baseline", "in-baseline template must not warn about its version")
	}
}

// TestUPPVersionLimitRejectsAboveBaseline drives the 2.3 fixture through a
// policy that only supports 2.1, so the template is above the baseline. The
// upload is refused with the stable code and /upp/validate still answers
// valid: true with a warning.
func TestUPPVersionLimitRejectsAboveBaseline(t *testing.T) {
	policy, err := service.NewSAIPVersionPolicy([]string{"2.1"})
	require.NoError(t, err)
	srv, _ := newTestServer(t, func(h *Handler) { h.AllowedSAIP = policy })
	base := srv.URL + "/admin/api/v1"

	data := uppFixture(t, "TS48v2_SAIP2.3_BERTLV.der")
	status, raw := do(t, "POST", base+"/upp", map[string]any{"name": "v23.der", "data": data})
	require.Equal(t, 409, status, string(raw))
	var body struct {
		Code    string         `json:"code"`
		Details map[string]any `json:"details"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Equal(t, "saip_version_not_supported", body.Code)
	require.Equal(t, "2.3", body.Details["templateVersion"])
	require.Equal(t, "2.1", body.Details["maxSupported"])

	status, raw = do(t, "POST", base+"/upp/validate", map[string]any{"data": data})
	require.Equal(t, 200, status, string(raw))
	var v struct {
		Valid    bool     `json:"valid"`
		Warnings []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.True(t, v.Valid)
	require.NotEmpty(t, v.Warnings)

	// The refused upload stored nothing.
	status, raw = do(t, "GET", base+"/upp/v23.der", nil)
	require.Equal(t, 404, status, string(raw))
}

// TestUPPValidateConstraintErrors pins N13 at the API boundary: a package that
// violates the V2.3.1 constraints is reported by /upp/validate (valid:false,
// errors[]) and refused by POST /upp without being stored.
func TestUPPValidateConstraintErrors(t *testing.T) {
	policy, err := service.NewSAIPVersionPolicy([]string{"2.3"})
	require.NoError(t, err)
	srv, _ := newTestServer(t, func(h *Handler) { h.AllowedSAIP = policy })
	base := srv.URL + "/admin/api/v1"

	// ProfileHeader (major 2, minor 3) + PE-MF, with no trailing PE-End.
	raw := []byte{0xa0, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0x03, 0xb0, 0x00}
	data := base64.StdEncoding.EncodeToString(raw)

	status, body := do(t, "POST", base+"/upp/validate", map[string]any{"data": data})
	require.Equal(t, 200, status, string(body))
	var v struct {
		Valid  bool     `json:"valid"`
		Errors []string `json:"errors"`
	}
	require.NoError(t, json.Unmarshal(body, &v))
	require.False(t, v.Valid)
	require.NotEmpty(t, v.Errors)

	status, body = do(t, "POST", base+"/upp", map[string]any{"name": "bad.der", "data": data})
	require.Equal(t, 400, status, string(body))
	require.Contains(t, string(body), "invalid_upp")

	// The refused template was not stored.
	status, _ = do(t, "GET", base+"/upp/bad.der", nil)
	require.Equal(t, 404, status)
}
