package admin

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"rsp42/internal/testutil"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAdminTenantsCRUDAndTenantFilters(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	// Create two tenants.
	for _, tenant := range []map[string]any{
		{"id": "carrier-a", "name": "Carrier A", "defaultUpp": "tpl-a"},
		{"id": "carrier-b", "name": "Carrier B"},
	} {
		status, _ := testutil.DoJSON(t, "POST", base+"/tenants", tenant)
		require.Equal(t, 200, status)
	}

	status, raw := testutil.DoJSON(t, "GET", base+"/tenants", nil)
	require.Equal(t, 200, status)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Len(t, list.Items, 2)

	// A PATCH keeps omitted fields.
	status, _ = testutil.DoJSON(t, "PATCH", base+"/tenants/carrier-a", map[string]any{"name": "Carrier A (renamed)"})
	require.Equal(t, 200, status)
	status, raw = testutil.DoJSON(t, "GET", base+"/tenants/carrier-a", nil)
	require.Equal(t, 200, status)
	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))
	require.Equal(t, "Carrier A (renamed)", got["name"])
	require.Equal(t, "tpl-a", got["defaultUpp"])

	// Profiles are attributable to a tenant and filterable by it.
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "carrier-a", "externalRef": "order-1"})
	require.Equal(t, 201, status)
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "carrier-b"})
	require.Equal(t, 201, status)

	status, raw = testutil.DoJSON(t, "GET", base+"/profiles?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	var profiles struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &profiles))
	require.Equal(t, 1, profiles.Total)
	require.Equal(t, "order-1", profiles.Items[0]["externalRef"])

	// externalRef is a supported filter.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles?externalRef=order-1", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":1`)

	// An unregistered tenant is refused on a write.
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "nobody"})
	require.Equal(t, 400, status)

	// N3: deleting a tenant that still owns resources is refused and reports
	// the usage counts for a pre-delete warning.
	status, raw = testutil.DoJSON(t, "DELETE", base+"/tenants/carrier-b", nil)
	require.Equal(t, 409, status, string(raw))
	var inUse struct {
		Code  string `json:"code"`
		Usage struct {
			Profiles int `json:"profiles"`
		} `json:"usage"`
	}
	require.NoError(t, json.Unmarshal(raw, &inUse))
	require.Equal(t, "tenant_in_use", inUse.Code)
	require.Equal(t, 1, inUse.Usage.Profiles)

	status, raw = testutil.DoJSON(t, "GET", base+"/tenants/carrier-b", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"profiles":1`)

	// force + reassignTo= (the platform-default scope) migrates then deletes.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/tenants/carrier-b?force=true&reassignTo=", nil)
	require.Equal(t, 204, status)
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles?tenant=carrier-b", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":0`)

	// The profile survived under the platform-default scope.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles?tenant=", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":1`)

	// force with an unregistered reassignTo target is refused.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/tenants/carrier-a?force=true&reassignTo=nobody", nil)
	require.Equal(t, 400, status)
	// A tenant cannot be reassigned to itself.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/tenants/carrier-a?force=true&reassignTo=carrier-a", nil)
	require.Equal(t, 400, status)
}

func TestAdminPoolTenantIsolation(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{"id": "carrier-a"})
	testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{"id": "carrier-b"})

	for _, imp := range []map[string]any{
		{"tenant": "carrier-a", "start": "8900012000000000000", "end": "8900012000000000099"},
		{"tenant": "carrier-b", "start": "8900022000000000000", "end": "8900022000000000099"},
	} {
		status, _ := testutil.DoJSON(t, "POST", base+"/iccid-ranges", imp)
		require.Equal(t, 201, status)
	}

	// A reservation never crosses tenant boundaries.
	status, raw := testutil.DoJSON(t, "POST", base+"/iccid-pool/reserve", map[string]any{"tenant": "carrier-a", "eid": "EID-A"})
	require.Equal(t, 200, status)
	var reserved map[string]any
	require.NoError(t, json.Unmarshal(raw, &reserved))
	require.True(t, strings.HasPrefix(reserved["iccid"].(string), "8900012"), "got %v", reserved)

	status, raw = testutil.DoJSON(t, "GET", base+"/iccid-pool?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "8900012")
	require.NotContains(t, string(raw), "8900022")

	// Stats are scoped too.
	status, raw = testutil.DoJSON(t, "GET", base+"/iccid-pool/stats?tenant=carrier-b", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"ranges":1`)

	// The profile created for carrier-a draws from carrier-a's range.
	status, raw = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "carrier-a"})
	require.Equal(t, 201, status)
	var created map[string]any
	require.NoError(t, json.Unmarshal(raw, &created))
	require.True(t, strings.HasPrefix(created["iccid"].(string), "8900012"), "got %v", created)
}

func TestAdminUPPTools(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	data := base64.StdEncoding.EncodeToString(der)

	// validate: structural inspection without storing.
	status, raw := testutil.DoJSON(t, "POST", base+"/upp/validate", map[string]any{"data": data})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"valid":true`)
	require.Contains(t, string(raw), `"saip":"2.1"`)

	status, raw = testutil.DoJSON(t, "POST", base+"/upp/validate", map[string]any{"data": base64.StdEncoding.EncodeToString([]byte("not a upp"))})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"valid":false`)

	// Store a global template.
	status, _ = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "u.der", "data": data})
	require.Equal(t, 200, status)

	// schema: the field catalog for the visual editor.
	status, raw = testutil.DoJSON(t, "GET", base+"/upp/u.der/schema", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"name":"plmn"`)
	require.Contains(t, string(raw), `"name":"imsi"`)

	// render: dry-run, allocates nothing.
	status, raw = testutil.DoJSON(t, "POST", base+"/upp/render", map[string]any{
		"name": "u.der", "iccid": "89000123456789012341", "imsi": "001010123456063",
	})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"rendered":true`)
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":0`)

	// clone a global template into a tenant.
	status, _ = testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{"id": "carrier-a"})
	require.Equal(t, 200, status)
	status, raw = testutil.DoJSON(t, "POST", base+"/upp/u.der/clone", map[string]any{"tenant": "carrier-a", "name": "u-a"})
	require.Equal(t, 201, status)
	require.Contains(t, string(raw), `"tenant":"carrier-a"`)

	status, raw = testutil.DoJSON(t, "GET", base+"/upp?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "u-a")
	require.Contains(t, string(raw), "u.der")

	// promote the tenant template to global.
	status, _ = testutil.DoJSON(t, "POST", base+"/upp/u-a/promote?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	// A second promote without overwrite conflicts.
	testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "u-a", "data": data})
	status, _ = testutil.DoJSON(t, "POST", base+"/upp/u-a/promote?tenant=carrier-a", nil)
	require.Equal(t, 409, status)
	status, _ = testutil.DoJSON(t, "POST", base+"/upp/u-a/promote?tenant=carrier-a&overwrite=1", nil)
	require.Equal(t, 200, status)
}

func TestAdminIdempotentCreateProfile(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	body := map[string]any{"profileType": "operational", "externalRef": "order-7"}
	req, err := http.NewRequest("POST", base+"/profiles", strings.NewReader(mustJSON(t, body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "create-7")

	firstStatus, _, firstRaw := doRead(t, req)
	require.Equal(t, 201, firstStatus)

	req2, err := http.NewRequest("POST", base+"/profiles", strings.NewReader(mustJSON(t, body)))
	require.NoError(t, err)
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", "create-7")
	secondStatus, secondHeader, secondRaw := doRead(t, req2)
	require.Equal(t, 201, secondStatus)
	require.JSONEq(t, firstRaw, secondRaw)
	require.Equal(t, "true", secondHeader.Get("Idempotency-Replayed"))

	status, raw := testutil.DoJSON(t, "GET", base+"/profiles", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":1`)
}

func TestAdminStatsAndNotifications(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational"})
	testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational"})

	status, raw := testutil.DoJSON(t, "GET", base+"/profiles/stats?groupBy=state", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"groupBy":"state"`)
	require.Contains(t, string(raw), "Allocated")

	status, _ = testutil.DoJSON(t, "GET", base+"/profiles/stats?groupBy=bogus", nil)
	require.Equal(t, 400, status)

	status, raw = testutil.DoJSON(t, "GET", base+"/audit/stats?groupBy=interface", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "admin")

	// Audit rows are attributed to the internal backend and the tenant.
	status, raw = testutil.DoJSON(t, "GET", base+"/audit?interface=admin", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"actor":"esim42-backend"`)

	status, raw = testutil.DoJSON(t, "GET", base+"/notifications", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":0`)
}

func TestAdminTimelineIncludesAudit(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	var created map[string]any
	_, raw := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational"})
	require.NoError(t, json.Unmarshal(raw, &created))
	iccid := created["iccid"].(string)

	testutil.DoJSON(t, "POST", base+"/profiles/"+iccid+"/confirm", map[string]any{"release": true})

	status, raw := testutil.DoJSON(t, "GET", base+"/profiles/"+iccid+"/timeline", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"kind":"order"`)
	require.Contains(t, string(raw), `"kind":"audit"`)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// doRead performs req and returns its status, headers and body, closing the body
// before returning. It deliberately does not return the *http.Response: the
// response value would escape the function, and neither the bodyclose linter nor
// a caller can tell that the body is already closed.
func doRead(t *testing.T, req *http.Request) (int, http.Header, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, string(b)
}

// TestAdminOpenAPIDocIsValid asserts the embedded OpenAPI description is
// well-formed and covers every mounted area (G10).
func TestAdminOpenAPIDocIsValid(t *testing.T) {
	srv, _ := newTestServer(t)
	status, raw := testutil.DoJSON(t, "GET", srv.URL+"/admin/api/v1/openapi.json", nil)
	require.Equal(t, 200, status)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Equal(t, "3.0.3", doc["openapi"])
	info, ok := doc["info"].(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, info["title"])

	comps, ok := doc["components"].(map[string]any)
	require.True(t, ok)
	schemas, ok := comps["schemas"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, schemas, "Error")

	paths, ok := doc["paths"].(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, paths)
	for path, item := range paths {
		ops, ok := item.(map[string]any)
		require.True(t, ok, "path %s must be an object", path)
		for method, op := range ops {
			if method == "parameters" {
				continue
			}
			opMap, ok := op.(map[string]any)
			require.True(t, ok, "%s %s must be an object", method, path)
			require.NotEmpty(t, opMap["summary"], "%s %s has no summary", method, path)
			require.NotEmpty(t, opMap["responses"], "%s %s has no responses", method, path)
		}
	}
	// Every mounted area is described.
	for _, want := range []string{
		"/admin/api/v1/tenants", "/admin/api/v1/profiles", "/admin/api/v1/profiles/stats",
		"/admin/api/v1/upp", "/admin/api/v1/upp/validate", "/admin/api/v1/upp/render",
		"/admin/api/v1/upp/{name}/schema", "/admin/api/v1/upp/{name}/clone", "/admin/api/v1/upp/{name}/promote",
		"/admin/api/v1/batches", "/admin/api/v1/audit", "/admin/api/v1/audit/stats",
		"/admin/api/v1/eids",
		"/admin/api/v1/upp/{name}/versions", "/admin/api/v1/upp/{name}/versions/{version}/restore",
		"/admin/api/v1/notifications", "/admin/api/v1/iccid-pool", "/admin/api/v1/iccid-pool/reserve",
		"/admin/api/v1/iccid-ranges", "/admin/api/v1/personalization", "/admin/api/v1/personalization/pool/import",
		"/admin/api/v1/events",
	} {
		require.Contains(t, paths, want)
	}
}

// TestAdminPersonalizationPoolPairing covers the G6 credentials pool path:
// credentials imported without an ICCID are paired when an ICCID is reserved.
func TestAdminPersonalizationPoolPairing(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{"id": "carrier-a"})
	status, _ := testutil.DoJSON(t, "POST", base+"/iccid-ranges", map[string]any{
		"tenant": "carrier-a", "start": "8900012000000000000", "end": "8900012000000000099",
	})
	require.Equal(t, 201, status)

	status, raw := testutil.DoJSON(t, "POST", base+"/personalization/pool/import", map[string]any{
		"tenant": "carrier-a",
		"records": []map[string]any{
			{"imsi": "001010000000001", "k": "465B5CE8B199B49FAA5F0A2EE238A6BC", "spn": "POOL"},
			{"imsi": "001010000000002"},
		},
	})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"imported":2`)

	// A record without an ICCID is listed as a pool entry.
	status, raw = testutil.DoJSON(t, "GET", base+"/personalization?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"pool":true`)

	// Reserving an ICCID pairs it with the next unbound IMSI.
	status, raw = testutil.DoJSON(t, "POST", base+"/iccid-pool/reserve", map[string]any{"tenant": "carrier-a"})
	require.Equal(t, 200, status)
	var reserved map[string]any
	require.NoError(t, json.Unmarshal(raw, &reserved))
	require.Equal(t, "001010000000001", reserved["imsi"])

	// The pairing is persisted: the credentials are now bound to that ICCID.
	status, raw = testutil.DoJSON(t, "GET", base+"/personalization/"+reserved["iccid"].(string)+"?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "001010000000001")
	require.NotContains(t, string(raw), `"pool":true`)

	// Stats expose the remaining unbound credentials.
	status, raw = testutil.DoJSON(t, "GET", base+"/iccid-pool/stats?tenant=carrier-a", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"credentials_unbound":1`)
}

// TestAdminStableErrorCodes covers the G10 error model: errors carry a stable
// machine-readable code alongside the HTTP status.
func TestAdminStableErrorCodes(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{"id": "carrier-a", "templateQuota": 1})

	// Unknown tenant.
	status, raw := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "nope"})
	require.Equal(t, 400, status)
	require.Contains(t, string(raw), `"code":"unknown_tenant"`)

	// Template quota.
	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	data := base64.StdEncoding.EncodeToString(der)
	status, _ = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "t1", "tenant": "carrier-a", "data": data})
	require.Equal(t, 200, status)
	status, raw = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "t2", "tenant": "carrier-a", "data": data})
	require.Equal(t, 409, status)
	require.Contains(t, string(raw), `"code":"quota_exceeded"`)

	// Replacing an existing template is always allowed.
	status, _ = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "t1", "tenant": "carrier-a", "data": data})
	require.Equal(t, 200, status)

	// Unknown ICCID on a read.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles/8900012345678901234", nil)
	require.Equal(t, 404, status)
	require.Contains(t, string(raw), `"code":"not_found"`)

	// Bad query parameter.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles/stats?groupBy=nonsense", nil)
	require.Equal(t, 400, status)
	require.Contains(t, string(raw), `"code":"invalid_request"`)
}

// TestAdminProfileQuota covers G15: tenants.profile_quota is enforced at
// allocation time with a stable error code.
func TestAdminProfileQuota(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{"id": "carrier-a", "profileQuota": 2})
	for i := 0; i < 2; i++ {
		status, _ := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "carrier-a"})
		require.Equal(t, 201, status)
	}
	status, raw := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "carrier-a"})
	require.Equal(t, 409, status)
	require.Contains(t, string(raw), `"code":"quota_exceeded"`)

	// Other tenants are unaffected by carrier-a's quota.
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{})
	require.Equal(t, 201, status)

	// Deleting a profile frees a slot.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles?tenant=carrier-a&size=1", nil)
	require.Equal(t, 200, status)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	status, _ = testutil.DoJSON(t, "DELETE", base+"/profiles/"+list.Items[0]["iccid"].(string), nil)
	require.Equal(t, 204, status)
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"tenant": "carrier-a"})
	require.Equal(t, 201, status)
}

// TestAdminEIDAggregationAndCSVImport covers G16: the per-EID aggregation view
// and CSV profile import with per-row error reporting.
func TestAdminEIDAggregationAndCSVImport(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	eid := "89049032123451234512345678901235"
	status, _ := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"eid": eid, "externalRef": "r1"})
	require.Equal(t, 201, status)
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"eid": eid, "externalRef": "r2"})
	require.Equal(t, 201, status)

	status, raw := testutil.DoJSON(t, "GET", base+"/eids", nil)
	require.Equal(t, 200, status)
	var agg struct {
		Items []struct {
			EID          string `json:"eid"`
			ProfileCount int    `json:"profileCount"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &agg))
	require.Equal(t, 1, agg.Total)
	require.Equal(t, eid, agg.Items[0].EID)
	require.Equal(t, 2, agg.Items[0].ProfileCount)

	// CSV import: two good rows and one duplicate ICCID reported individually.
	csvBody := "iccid,eid,profileType,externalRef\n" +
		"89000123456789012341,," + "operational,c1\n" +
		"89000123456789012342,," + "operational,c2\n" +
		"89000123456789012341,," + "operational,dup\n"
	req, err := http.NewRequest("POST", base+"/profiles/import", strings.NewReader(csvBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "text/csv")
	status, _, body := doRead(t, req)
	require.Equal(t, 200, status)
	require.Contains(t, body, `"imported":2`)
	require.Contains(t, body, `"ok":false`)

	// The CSV and JSON paths accept the same records.
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles/import", map[string]any{
		"records": []map[string]any{{"iccid": "89000123456789012343", "profileType": "operational"}},
	})
	require.Equal(t, 200, status)
}

// TestAdminUPPVersionHistory covers G18: replacing a template archives the
// previous revision and it can be rolled back.
func TestAdminUPPVersionHistory(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	data := base64.StdEncoding.EncodeToString(der)

	// First upload: nothing to archive yet.
	status, raw := testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "hist", "data": data})
	require.Equal(t, 200, status)
	var first map[string]any
	require.NoError(t, json.Unmarshal(raw, &first))
	firstSha := first["sha256"].(string)

	status, raw = testutil.DoJSON(t, "GET", base+"/upp/hist/versions", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":0`)

	// Re-upload different bytes: the original revision is archived.
	other, err := os.ReadFile("../../../testdata/upp/TS48v1_B.der")
	require.NoError(t, err)
	status, raw = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "hist", "data": base64.StdEncoding.EncodeToString(other)})
	require.Equal(t, 200, status)
	var second map[string]any
	require.NoError(t, json.Unmarshal(raw, &second))
	require.NotEqual(t, firstSha, second["sha256"])

	status, raw = testutil.DoJSON(t, "GET", base+"/upp/hist/versions", nil)
	require.Equal(t, 200, status)
	var versions struct {
		Items []struct {
			ID        int64  `json:"id"`
			VersionNo int    `json:"versionNo"`
			SHA256    string `json:"sha256"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &versions))
	require.Equal(t, 1, versions.Total)
	require.Equal(t, 1, versions.Items[0].VersionNo)
	require.Equal(t, firstSha, versions.Items[0].SHA256)

	// Roll back to it.
	status, raw = testutil.DoJSON(t, "POST", base+"/upp/hist/versions/"+strconv.FormatInt(versions.Items[0].ID, 10)+"/restore", nil)
	require.Equal(t, 200, status)
	var restored map[string]any
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, firstSha, restored["sha256"])

	// The rollback archived what it replaced, so the history now has two rows.
	status, raw = testutil.DoJSON(t, "GET", base+"/upp/hist/versions", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":2`)

	// Unknown versions are a 404.
	status, _ = testutil.DoJSON(t, "POST", base+"/upp/hist/versions/9999/restore", nil)
	require.Equal(t, 404, status)
}
