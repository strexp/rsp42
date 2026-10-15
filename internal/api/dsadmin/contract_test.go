package dsadmin_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"rsp42/internal/api/openapi"
	"rsp42/internal/testutil"
)

// The SM-DS management API serves a view of the shared OpenAPI document that is
// restricted to the paths it mounts (openapi.FilteredDoc). These tests check
// that view the same way the SM-DP+ admin checks the full one: every 2xx body is
// declared and the real responses match the declared schema.

func compileSchema(t *testing.T, doc map[string]any, name string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource("dsadmin.json", doc))
	sch, err := c.Compile("dsadmin.json#/components/schemas/" + name)
	require.NoError(t, err, "schema %s must compile in the filtered document", name)
	return sch
}

func declaredSchema(t *testing.T, doc map[string]any, path, method string) *jsonschema.Schema {
	t.Helper()
	paths, _ := doc["paths"].(map[string]any)
	item, ok := paths[path].(map[string]any)
	require.True(t, ok, "path %s is not in the filtered document", path)
	op, _ := item[method].(map[string]any)
	responses, _ := op["responses"].(map[string]any)
	resp, _ := responses["200"].(map[string]any)
	content, _ := resp["content"].(map[string]any)
	media, _ := content["application/json"].(map[string]any)
	schema, _ := media["schema"].(map[string]any)
	ref, _ := schema["$ref"].(string)
	require.True(t, strings.HasPrefix(ref, "#/components/schemas/"), "path %s declares %v", path, schema)
	return compileSchema(t, doc, strings.TrimPrefix(ref, "#/components/schemas/"))
}

func TestDSAdminResponsesMatchTheFilteredDocument(t *testing.T) {
	doc := openapi.FilteredDoc("rsp42 SM-DS management API", "test", "/admin/api/v1/events")
	srv, _ := newDSTestServer(t)
	base := srv.URL + "/admin/api/v1"

	// The event list declares items/total and matches it.
	status, raw := testutil.DoJSON(t, "GET", base+"/events", nil)
	require.EqualValues(t, 200, status, string(raw))
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Contains(t, body, "items")
	validate := func(sch *jsonschema.Schema, raw []byte) {
		t.Helper()
		var v any
		require.NoError(t, json.Unmarshal(raw, &v))
		require.NoError(t, sch.Validate(v), "payload does not match the declared schema:\n%s", string(raw))
	}
	validate(declaredSchema(t, doc, "/admin/api/v1/events", "get"), raw)

	// The created event matches the Event schema.
	status, raw = testutil.DoJSON(t, "POST", base+"/events", map[string]any{
		"eid": "89049032000000000000000000000001", "eventId": "EVT-CONTRACT",
		"rspServerAddress": "smdp.example",
	})
	require.EqualValues(t, 201, status, string(raw))
	validate(compileSchema(t, doc, "Event"), raw)

	// Every path in the view declares a JSON schema (or is a 204).
	paths, _ := doc["paths"].(map[string]any)
	require.NotEmpty(t, paths)
	for path, item := range paths {
		ops, _ := item.(map[string]any)
		for method, op := range ops {
			if method == "parameters" {
				continue
			}
			opMap, _ := op.(map[string]any)
			responses, _ := opMap["responses"].(map[string]any)
			for status, r := range responses {
				if !strings.HasPrefix(status, "2") || status == "204" {
					continue
				}
				resp, _ := r.(map[string]any)
				require.NotEmpty(t, resp["content"], "%s %s %s documents no body", method, path, status)
			}
		}
	}
}
