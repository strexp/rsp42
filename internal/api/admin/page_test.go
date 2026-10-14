package admin

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParsePage pins the shared ?page=/?size= parsing semantics: the
// management-API defaults (1/50) and bounds (page >= 1, size <= 500) must not
// drift from openapi.json.
func TestParsePage(t *testing.T) {
	cases := []struct {
		query    string
		wantPage int
		wantSize int
	}{
		{"", 1, 50},
		{"page=3&size=10", 3, 10},
		{"page=0", 1, 50},
		{"page=-4", 1, 50},
		{"page=abc", 1, 50},
		{"size=0", 1, 50},
		{"size=-1", 1, 50},
		{"size=501", 1, 500},
		{"size=500", 1, 500},
		{"size=abc", 1, 50},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?"+tc.query, nil)
			page, size := parsePage(r)
			require.Equal(t, tc.wantPage, page)
			require.Equal(t, tc.wantSize, size)
		})
	}
}

// TestWriteListEnvelope pins the shared list body shape.
func TestWriteListEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	writeListEnvelope(rec, []int{1, 2}, 2, 10, 3)
	// writeJSON terminates the body with a newline, as every admin response does.
	require.Equal(t, `{"items":[1,2],"page":2,"size":10,"total":3}`+"\n", rec.Body.String())
}
