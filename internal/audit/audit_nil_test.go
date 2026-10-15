package audit

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/store"
)

// The consumer-defined sink must be satisfied by the SQLite repository without
// the audit package depending on the concrete type.
var _ AuditSink = (*store.AuditRepo)(nil)

// TestDBSinkRejectsAbsentStore covers both ways "no store" can be expressed: a
// nil interface and a typed nil pointer stored in the interface. The latter is
// not == nil, so a plain comparison would let it through and panic on the first
// write.
func TestDBSinkRejectsAbsentStore(t *testing.T) {
	_, err := New(nil, "db", "")
	require.Error(t, err)

	var typedNil *store.AuditRepo
	_, err = New(typedNil, "db", "")
	require.Error(t, err)
}

// TestFileSinkNeedsNoStore pins that a file-only sink works with no repository.
func TestFileSinkNeedsNoStore(t *testing.T) {
	l, err := New(nil, "file", t.TempDir()+"/audit.log")
	require.NoError(t, err)
	require.NoError(t, l.Close())
}

// TestUnknownSinkRejected pins that a sink the logger cannot honour fails
// instead of returning a logger that writes nowhere.
func TestUnknownSinkRejected(t *testing.T) {
	for _, sink := range []string{"", "DB", "database", "stdout"} {
		l, err := New(nil, sink, "")
		require.ErrorContains(t, err, "is not supported", "sink %q", sink)
		require.Nil(t, l)
	}
}
