package adminhttp

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
			page, size := ParsePage(r)
			require.Equal(t, tc.wantPage, page)
			require.Equal(t, tc.wantSize, size)
		})
	}
}

// TestWriteListEnvelope pins the shared list body shape.
func TestWriteListEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteListEnvelope(rec, []int{1, 2}, 2, 10, 3)
	// WriteJSON terminates the body with a newline, as every admin response does.
	require.Equal(t, `{"items":[1,2],"page":2,"size":10,"total":3}`+"\n", rec.Body.String())
}

// TestErrorModel pins the stable {code,message} body and the status->code
// mapping that the management API contract documents (G10/N7).
func TestErrorModel(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteErr(rec, 404, "profile not found")
	require.Equal(t, 404, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, `{"code":"not_found","message":"profile not found"}`+"\n", rec.Body.String())

	require.Equal(t, "invalid_request", ErrCode(400))
	require.Equal(t, "conflict", ErrCode(409))
	require.Equal(t, "internal_error", ErrCode(503))
	require.Equal(t, "request_failed", ErrCode(418))
}

func TestParseIDAndTenantFilter(t *testing.T) {
	id, err := ParseID("42")
	require.NoError(t, err)
	require.EqualValues(t, 42, id)
	for _, bad := range []string{"", "0", "-1", "x"} {
		_, err := ParseID(bad)
		require.Error(t, err, "input %q", bad)
	}

	r := httptest.NewRequest("GET", "/?tenant=carrier-a", nil)
	require.Equal(t, "carrier-a", *TenantFilter(r))

	r = httptest.NewRequest("GET", "/?tenant=", nil)
	require.Equal(t, "", *TenantFilter(r), "an empty value selects the platform-default rows")

	r = httptest.NewRequest("GET", "/", nil)
	require.Nil(t, TenantFilter(r))
}
