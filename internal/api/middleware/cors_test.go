package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCORS(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	h := Chain(ok, CORS([]string{"http://example.com"}))

	// Preflight from an allowed origin.
	req := httptest.NewRequest(http.MethodOptions, "/admin/api/v1/profiles", nil)
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Equal(t, "http://example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "POST")
	require.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	require.Contains(t, rec.Header().Get("Vary"), "Origin")

	// A disallowed origin gets no allow header.
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))

	// Wildcard allows any origin.
	hw := Chain(ok, CORS([]string{"*"}))
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "http://any.example")
	rec = httptest.NewRecorder()
	hw.ServeHTTP(rec, req)
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
}
