package admin

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// openapiJSON is the complete OpenAPI 3.0 description of the management API. It
// is embedded so the served contract cannot drift from the repository copy, and
// it is asserted by TestOpenAPIDocIsValid.
//
//go:embed openapi.json
var openapiJSON []byte

var (
	openAPIDocOnce sync.Once
	openAPIDocMap  map[string]any
)

// openAPIDoc returns the parsed OpenAPI document. The embedded file is
// validated at init time by the test suite, so a parse failure here is a
// programming error.
func openAPIDoc() map[string]any {
	openAPIDocOnce.Do(func() {
		if err := json.Unmarshal(openapiJSON, &openAPIDocMap); err != nil {
			panic("admin: embedded openapi.json is not valid JSON: " + err.Error())
		}
	})
	return openAPIDocMap
}
