package admin

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"rsp42/internal/api/admin/openapi"
	"rsp42/internal/testutil"
)

// Management-API contract tests.
//
// The OpenAPI document is embedded and served as the interface contract
// (docs/interfaces.md, G10). These tests compile the published schemas with the
// pinned jsonschema library and validate real responses against the schema the
// document declares *for that operation*, so a handler change that drifts from
// the document fails here.
//
// The schemas use OpenAPI's "#/components/schemas/<name>" pointers, which are
// valid JSON Pointers into the same document, so the whole document is
// registered as one resource and the subschemas are compiled by that URL.

const apiPrefix = "/admin/api/v1"

func compileSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("openapi.json", openapi.Doc()))
	sch, err := c.Compile("openapi.json#/components/schemas/" + name)
	require.NoError(t, err, "schema %s must compile", name)
	return sch
}

// declaredSchema compiles the JSON response schema the document declares for one
// operation, so the assertion follows the contract rather than a name picked by
// the test.
func declaredSchema(t *testing.T, path, method, status string) *jsonschema.Schema {
	t.Helper()
	doc := openapi.Doc()
	paths, _ := doc["paths"].(map[string]any)
	item, ok := paths[path].(map[string]any)
	require.True(t, ok, "path %s is not documented", path)
	op, ok := item[method].(map[string]any)
	require.True(t, ok, "%s %s is not documented", method, path)
	responses, _ := op["responses"].(map[string]any)
	resp, ok := responses[status].(map[string]any)
	require.True(t, ok, "%s %s has no documented %s response", method, path, status)
	// A response may be declared inline or referenced from components.responses
	// (the shared Error response).
	if r, ok := resp["$ref"].(string); ok {
		components, _ := doc["components"].(map[string]any)
		all, _ := components["responses"].(map[string]any)
		name := strings.TrimPrefix(r, "#/components/responses/")
		require.NotEqual(t, r, name, "unexpected response ref %q", r)
		resp, ok = all[name].(map[string]any)
		require.True(t, ok, "%s %s %s references unknown response %q", method, path, status, r)
	}
	content, _ := resp["content"].(map[string]any)
	media, ok := content["application/json"].(map[string]any)
	require.True(t, ok, "%s %s %s has no application/json body", method, path, status)
	schema, _ := media["schema"].(map[string]any)
	ref, _ := schema["$ref"].(string)
	require.True(t, strings.HasPrefix(ref, "#/components/schemas/"),
		"%s %s %s declares an unexpected schema %v", method, path, status, schema)
	return compileSchema(t, strings.TrimPrefix(ref, "#/components/schemas/"))
}

func validateAgainst(t *testing.T, sch *jsonschema.Schema, raw []byte) {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NoError(t, sch.Validate(v), "payload does not match the declared schema:\n%s", string(raw))
}

// TestEveryJSONResponseIsDocumented walks the whole document: every 2xx answer
// must either be 204 (no body), a documented non-JSON payload, or declare an
// application/json schema that compiles.
func TestEveryJSONResponseIsDocumented(t *testing.T) {
	doc := openapi.Doc()
	paths, _ := doc["paths"].(map[string]any)
	operations := 0
	for path, item := range paths {
		ops, ok := item.(map[string]any)
		require.True(t, ok)
		for method, op := range ops {
			if method == "parameters" {
				continue
			}
			operations++
			opMap, _ := op.(map[string]any)
			responses, _ := opMap["responses"].(map[string]any)
			for status, r := range responses {
				if !strings.HasPrefix(status, "2") {
					continue
				}
				resp, _ := r.(map[string]any)
				if status == "204" {
					require.NotContains(t, resp, "content", "%s %s %s must have no body", method, path, status)
					continue
				}
				content, _ := resp["content"].(map[string]any)
				require.NotEmpty(t, content, "%s %s %s documents no body", method, path, status)
				if _, err := json.Marshal(content); err != nil {
					t.Fatalf("%s %s: %v", method, path, err)
				}
				// An application/json body must reference a schema that compiles.
				if media, ok := content["application/json"].(map[string]any); ok {
					schema, _ := media["schema"].(map[string]any)
					ref, _ := schema["$ref"].(string)
					require.True(t, strings.HasPrefix(ref, "#/components/schemas/"),
						"%s %s %s has no schema reference", method, path, status)
					compileSchema(t, strings.TrimPrefix(ref, "#/components/schemas/"))
				}
			}
		}
	}
	require.Greater(t, operations, 60, "the document must describe the whole management surface")
}

// TestErrorPathsMatchTheDeclaredSchema drives the failure paths of several
// resources and validates each body against the schema the document declares for
// that operation and status.
func TestErrorPathsMatchTheDeclaredSchema(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + apiPrefix

	cases := []struct {
		name   string
		method string
		// call is the concrete URL suffix; doc is the documented template.
		call, doc string
		body      any
		status    string
	}{
		{"unknown tenant", "GET", "/tenants/nope", "/tenants/{id}", nil, "404"},
		{"invalid json", "POST", "/profiles", "/profiles", "not-an-object", "400"},
		{"malformed iccid", "POST", "/profiles", "/profiles", map[string]any{"iccid": "12345"}, "400"},
		{"unknown profile", "GET", "/profiles/89999999999999999999", "/profiles/{iccid}", nil, "404"},
		{"invalid upp version", "POST", "/upp/validate", "/upp/validate", map[string]any{"data": "!!!"}, "400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, raw := testutil.DoJSON(t, tc.method, base+tc.call, tc.body)
			require.Equal(t, tc.status, itoaStatus(status), string(raw))
			validateAgainst(t, declaredSchema(t, apiPrefix+tc.doc, strings.ToLower(tc.method), tc.status), raw)
		})
	}
}

// TestListResponsesMatchTheDeclaredSchema validates every list endpoint against
// the schema the document declares, and additionally pins that the paging fields
// are present exactly when the operation documents them (so the two envelopes
// cannot be confused silently).
func TestListResponsesMatchTheDeclaredSchema(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + apiPrefix

	// Paginated lists: page/size/total plus items (components/schemas/Page).
	paths := []string{
		"/profiles", "/batches", "/iccid-pool", "/personalization",
		"/callbacks", "/notifications", "/audit", "/eids",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			status, raw := testutil.DoJSON(t, "GET", base+path, nil)
			require.EqualValues(t, 200, status, string(raw))
			validateAgainst(t, declaredSchema(t, apiPrefix+path, "get", "200"), raw)

			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))
			require.Contains(t, body, "items")
			require.Contains(t, body, "total", "%s must report a total", path)
			require.Contains(t, body, "page")
			require.Contains(t, body, "size")
			_ = body

			// /audit has a second shape in cursor mode; the documented response
			// accepts both (components/schemas/AuditResponse) and the cursor
			// body carries no paging fields.
			if path == "/audit" {
				status, raw = testutil.DoJSON(t, "GET", base+path+"?afterId=0&limit=5", nil)
				require.EqualValues(t, 200, status, string(raw))
				validateAgainst(t, declaredSchema(t, apiPrefix+path, "get", "200"), raw)
				var cursor map[string]any
				require.NoError(t, json.Unmarshal(raw, &cursor))
				require.Contains(t, cursor, "nextAfterId")
				require.Contains(t, cursor, "hasMore")
				require.NotContains(t, cursor, "page")
			}
		})
	}

	// The unbounded lists document items/total only.
	for _, path := range []string{"/tenants", "/upp", "/iccid-ranges"} {
		t.Run(path+" (unbounded)", func(t *testing.T) {
			status, raw := testutil.DoJSON(t, "GET", base+path, nil)
			require.EqualValues(t, 200, status, string(raw))
			validateAgainst(t, declaredSchema(t, apiPrefix+path, "get", "200"), raw)

			var body map[string]any
			require.NoError(t, json.Unmarshal(raw, &body))
			require.Contains(t, body, "total")
			require.NotContains(t, body, "page")
		})
	}
}

// TestResourceResponsesMatchTheDeclaredSchema validates the object-returning
// endpoints, including a create/read pair for each of the three main resources.
func TestResourceResponsesMatchTheDeclaredSchema(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + apiPrefix

	// Profile: create, read and mutate all answer with the Profile schema.
	status, raw := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{
		"iccid": "89000123456789012341", "profileType": "operational",
	})
	require.EqualValues(t, 201, status, string(raw))
	profileSchema := declaredSchema(t, apiPrefix+"/profiles", "post", "201")
	validateAgainst(t, profileSchema, raw)

	status, raw = testutil.DoJSON(t, "GET", base+"/profiles/89000123456789012341", nil)
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/profiles/{iccid}", "get", "200"), raw)

	status, raw = testutil.DoJSON(t, "POST", base+"/profiles/89000123456789012341/confirm", map[string]any{})
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/profiles/{iccid}/confirm", "post", "200"), raw)

	// Tenant: upsert and read.
	status, raw = testutil.DoJSON(t, "POST", base+"/tenants", map[string]any{
		"id": "carrier-contract", "name": "Contract Carrier",
	})
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/tenants", "post", "200"), raw)

	status, raw = testutil.DoJSON(t, "GET", base+"/tenants/carrier-contract", nil)
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/tenants/{id}", "get", "200"), raw)

	// UPP template: upload and read.
	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	status, raw = testutil.DoJSON(t, "POST", base+"/upp", map[string]any{
		"name": "contract.der", "data": base64.StdEncoding.EncodeToString(der),
	})
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/upp", "post", "200"), raw)

	status, raw = testutil.DoJSON(t, "GET", base+"/upp/contract.der/schema", nil)
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/upp/{name}/schema", "get", "200"), raw)

	status, raw = testutil.DoJSON(t, "GET", base+"/upp/contract.der/decoded", nil)
	require.EqualValues(t, 200, status, string(raw))
	validateAgainst(t, declaredSchema(t, apiPrefix+"/upp/{name}/decoded", "get", "200"), raw)
}

// TestCreateProfileRequestMatchesTheDocumentedSchema validates the request body
// shape against the documented schema, so a caller generated from the contract
// can talk to the endpoint.
func TestCreateProfileRequestMatchesTheDocumentedSchema(t *testing.T) {
	sch := compileSchema(t, "CreateProfileRequest")
	require.NoError(t, sch.Validate(map[string]any{
		"iccid": "89000123456789012341", "profileType": "operational", "externalRef": "crm-1",
	}))
	// A body with a wrong type must be rejected by the documented schema.
	require.Error(t, sch.Validate(map[string]any{"iccid": 42}))
}

func itoaStatus(status int) string {
	switch status {
	case 400:
		return "400"
	case 404:
		return "404"
	case 409:
		return "409"
	default:
		return ""
	}
}
