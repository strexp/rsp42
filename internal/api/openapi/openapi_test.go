package openapi

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDocIsWellFormedAndComplete pins the embedded document: it parses, every
// operation has a summary and responses, and the SM-DS events endpoints are
// described (they are served by the dsadmin surface from this same file).
func TestDocIsWellFormedAndComplete(t *testing.T) {
	doc := Doc()
	require.Equal(t, "3.0.3", doc["openapi"])

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
	require.Contains(t, paths, "/admin/api/v1/events")
	require.Contains(t, paths, "/admin/api/v1/events/{id}")
}

// TestFilteredDocKeepsOnlyRequestedPaths pins the role-specific view: the
// sub-path of a requested path is kept, unrelated paths and their tags are
// dropped, and the title reflects the narrower surface.
func TestFilteredDocKeepsOnlyRequestedPaths(t *testing.T) {
	doc := FilteredDoc("scoped title", "scoped description", "/admin/api/v1/events")

	paths, ok := doc["paths"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, paths, "/admin/api/v1/events")
	require.Contains(t, paths, "/admin/api/v1/events/{id}")
	require.NotContains(t, paths, "/admin/api/v1/profiles")
	require.NotContains(t, paths, "/admin/api/v1/upp")

	info, ok := doc["info"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "scoped title", info["title"])
	require.Equal(t, "scoped description", info["description"])

	// The full document is untouched by filtering.
	full := Doc()
	fullPaths, _ := full["paths"].(map[string]any)
	require.Contains(t, fullPaths, "/admin/api/v1/profiles")
}
