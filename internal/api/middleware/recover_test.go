package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRecoverReturnsJSON500 pins that a panic is reported as a parseable JSON
// body (SGP.22 §6.2 defines an RSP envelope only for HTTP 200, so a 5xx is a
// JSON HTTP-level error, not a functionExecutionStatus).
func TestRecoverReturnsJSON500(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))

	h := Recover(log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "internal server error", body["error"])

	// The panic detail is logged (with a stack trace), not returned.
	require.Contains(t, logged.String(), "kaboom")
	require.Contains(t, logged.String(), "goroutine")
}
