package admin

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"rsp42/internal/api/admin/openapi"
	"rsp42/internal/testutil"
)

// Management-API contract tests.
//
// The OpenAPI document is embedded and served as the interface contract
// (docs/interfaces.md, G10), but nothing checked that the payloads the handlers
// actually produce conform to it. These tests compile the published schemas with
// the pinned jsonschema library and validate real responses against them, so a
// handler change that drifts from the document fails here.
//
// The schemas use OpenAPI's "#/components/schemas/<name>" pointers, which are
// valid JSON Pointers into the same document, so the whole document is
// registered as one resource and the subschemas are compiled by that URL.

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("openapi.json", openapi.Doc()))
	sch, err := c.Compile("openapi.json#/components/schemas/" + name)
	require.NoError(t, err, "schema %s must compile", name)
	return sch
}

func validateAgainst(t *testing.T, sch *jsonschema.Schema, raw []byte) {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NoError(t, sch.Validate(v), "payload does not match the schema:\n%s", string(raw))
}

// TestErrorBodiesMatchThePublishedSchema drives the failure paths of several
// resources and validates each body against components.schemas.Error.
func TestErrorBodiesMatchThePublishedSchema(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"
	sch := compileSchema(t, "Error")

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		status int
	}{
		{"unknown tenant", "GET", "/tenants/nope", nil, 404},
		{"invalid json", "POST", "/profiles", "not-an-object", 400},
		// A malformed ICCID is reported as 409 conflict by createProfile, which
		// maps every allocation failure to conflict. Recording it here keeps the
		// behaviour pinned; the status-code precision is a follow-up in
		// docs/refactoring-plan.md (a malformed value is arguably 400
		// invalid_request).
		{"malformed iccid", "POST", "/profiles", map[string]any{"iccid": "12345"}, 409},
		{"unknown profile", "GET", "/profiles/89999999999999999999", nil, 404},
		{"invalid upp version", "POST", "/upp/validate", map[string]any{"data": "!!!"}, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, raw := testutil.DoJSON(t, tc.method, base+tc.path, tc.body)
			require.Equal(t, tc.status, status, string(raw))
			validateAgainst(t, sch, raw)
		})
	}
}

// TestListEnvelopesMatchTheirPublishedShape pins the two list envelopes the
// management API uses: the paginated one (page/size/total plus items, described
// by components.schemas.Page) and the unbounded one (items/total, which the
// document does not describe — see the report note in docs/refactoring-plan.md).
func TestListEnvelopesMatchTheirPublishedShape(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"
	pageSchema := compileSchema(t, "Page")

	// Endpoints that list everything unfiltered: items/total, no paging
	// parameters. /iccid-ranges is items-only, which is the one list shape that
	// does not carry a total (recorded as a follow-up in the plan document).
	unbounded := map[string]bool{"/tenants": true, "/upp": true, "/iccid-ranges": true}
	for _, path := range []string{
		"/profiles", "/upp", "/batches", "/iccid-pool", "/iccid-ranges", "/personalization",
		"/callbacks", "/notifications", "/audit", "/eids", "/tenants",
	} {
		t.Run(path, func(t *testing.T) {
			status, raw := testutil.DoJSON(t, "GET", base+path, nil)
			require.Equal(t, 200, status, string(raw))

			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))
			require.Contains(t, body, "items", "every list endpoint returns items")

			if unbounded[path] {
				require.NotContains(t, body, "page", "%s lists everything and has no page parameter", path)
				if path != "/iccid-ranges" {
					require.Contains(t, body, "total")
				}
				return
			}
			// A paginated list must satisfy the published Page schema.
			validateAgainst(t, pageSchema, raw)
			require.Contains(t, body, "size")
			require.Contains(t, body, "total")
		})
	}
}

// TestResourceBodiesMatchThePublishedSchemas validates the objects the API
// returns against the per-resource schemas, including the request/response pair
// for profile creation.
func TestResourceBodiesMatchThePublishedSchemas(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	// A created profile matches components.schemas.Profile.
	status, raw := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{
		"iccid": "89000123456789012341", "profileType": "operational",
	})
	require.Equal(t, 201, status, string(raw))
	validateAgainst(t, compileSchema(t, "Profile"), raw)

	// The tenant registry object matches components.schemas.Tenant.
	status, raw = testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{
		"id": "carrier-contract", "name": "Contract Carrier",
	})
	require.Contains(t, []int{200, 201}, status, string(raw))
	validateAgainst(t, compileSchema(t, "Tenant"), raw)

	// The UPP registry object matches components.schemas.UPPTemplate.
	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	status, raw = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{
		"name": "contract.der", "data": base64.StdEncoding.EncodeToString(der),
	})
	require.Equal(t, 200, status, string(raw))
	validateAgainst(t, compileSchema(t, "UPPTemplate"), raw)

	// The documented request schema accepts the body the API expects, so a
	// caller generated from the contract can talk to the real endpoint.
	require.NoError(t, compileSchema(t, "CreateProfileRequest").Validate(map[string]any{
		"iccid": "89000123456789012341", "profileType": "operational",
	}))
}
