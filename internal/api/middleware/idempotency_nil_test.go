package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/store"
)

// The consumer-defined store must be satisfied by the SQLite repository.
var _ IdempotencyStore = (*store.IdempotencyRepo)(nil)

// TestIdempotencyTypedNilStoreIsDisabled pins the nil guard: a typed nil
// *store.IdempotencyRepo stored in the interface is not == nil, so the plain
// comparison used before would have reached Claim on a nil receiver.
func TestIdempotencyTypedNilStoreIsDisabled(t *testing.T) {
	var repo *store.IdempotencyRepo
	called := false
	h := Idempotency(repo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Idempotency-Key", "k1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.True(t, called, "the handler must run when no store is configured")
	require.Equal(t, http.StatusNoContent, rec.Code)
}

func TestNilStore(t *testing.T) {
	require.True(t, nilStore(nil))
	var typedNil *store.IdempotencyRepo
	require.True(t, nilStore(typedNil))
	require.False(t, nilStore(&struct{}{}))
	require.False(t, nilStore("x"))
}
