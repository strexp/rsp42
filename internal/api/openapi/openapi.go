// Package openapi embeds and exposes the OpenAPI 3.0 description of the rsp42
// management API.
//
// The document describes the whole management surface (the SM-DP+ resources and
// the SM-DS /events endpoints). Doc returns it as-is for the SM-DP+ admin, and
// FilteredDoc returns a view restricted to the paths a surface actually mounts,
// so the SM-DS admin cannot advertise routes it does not serve.
package openapi

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

// openapiJSON is the complete OpenAPI 3.0 description. It is embedded so the
// served contract cannot drift from the repository copy, and the test suite
// asserts it is well-formed and covers every mounted area.
//
//go:embed openapi.json
var openapiJSON []byte

var (
	docOnce sync.Once
	docMap  map[string]any
)

// Doc returns the parsed management-API description. The embedded file is
// validated by the test suite, so a parse failure here is a programming error.
func Doc() map[string]any {
	docOnce.Do(func() {
		if err := json.Unmarshal(openapiJSON, &docMap); err != nil {
			panic("openapi: embedded openapi.json is not valid JSON: " + err.Error())
		}
	})
	return docMap
}

// FilteredDoc returns the description restricted to keepPaths and their
// sub-paths (so "/admin/api/v1/events" also keeps
// "/admin/api/v1/events/{id}"), keeping only the tags those operations use.
// title and description replace the full document's, because a partial document
// must not claim to describe the whole management surface. Paths that were not
// requested are dropped, which is what makes a role-specific view honest.
func FilteredDoc(title, description string, keepPaths ...string) map[string]any {
	full := Doc()
	paths, _ := full["paths"].(map[string]any)

	filtered := make(map[string]any, len(keepPaths))
	usedTags := map[string]bool{}
	for path, item := range paths {
		if !matchesAny(path, keepPaths) {
			continue
		}
		filtered[path] = item
		collectTags(item, usedTags)
	}

	out := make(map[string]any, len(full))
	for k, v := range full {
		out[k] = v
	}
	out["paths"] = filtered
	out["info"] = filteredInfo(full, title, description)
	if tags, ok := full["tags"].([]any); ok {
		out["tags"] = filterTags(tags, usedTags)
	}
	return out
}

func matchesAny(path string, keep []string) bool {
	for _, want := range keep {
		if path == want || strings.HasPrefix(path, want+"/") {
			return true
		}
	}
	return false
}

func collectTags(item any, used map[string]bool) {
	ops, ok := item.(map[string]any)
	if !ok {
		return
	}
	for method, op := range ops {
		if method == "parameters" {
			continue
		}
		opMap, ok := op.(map[string]any)
		if !ok {
			continue
		}
		tags, ok := opMap["tags"].([]any)
		if !ok {
			continue
		}
		for _, t := range tags {
			if s, ok := t.(string); ok {
				used[s] = true
			}
		}
	}
}

// filteredInfo copies the info object with the caller's title and description.
func filteredInfo(full map[string]any, title, description string) map[string]any {
	info, _ := full["info"].(map[string]any)
	out := make(map[string]any, len(info))
	for k, v := range info {
		out[k] = v
	}
	out["title"] = title
	out["description"] = description
	return out
}

func filterTags(tags []any, used map[string]bool) []any {
	out := make([]any, 0, len(tags))
	for _, t := range tags {
		m, ok := t.(map[string]any)
		if !ok {
			out = append(out, t)
			continue
		}
		name, _ := m["name"].(string)
		if used[name] {
			out = append(out, t)
		}
	}
	return out
}
