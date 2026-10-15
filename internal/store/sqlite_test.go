package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyDSNDefaults(t *testing.T) {
	const all = "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

	cases := []struct {
		name, in, want string
	}{
		{
			"a plain file DSN gets every default",
			"file:db/x.db",
			"file:db/x.db" + all,
		},
		{
			"existing query parameters are kept",
			"file:db/x.db?cache=shared",
			"file:db/x.db?cache=shared&_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
		},
		{
			"only the missing defaults are added",
			"file:db/x.db?_pragma=busy_timeout(5000)",
			"file:db/x.db?_pragma=busy_timeout(5000)&_txlock=immediate&_pragma=journal_mode(WAL)",
		},
		{
			"a fully specified DSN is untouched",
			"file:db/x.db" + all,
			"file:db/x.db" + all,
		},
		{
			"a private in-memory DSN is untouched",
			":memory:",
			":memory:",
		},
		{
			"a file in-memory DSN is untouched",
			"file::memory:?cache=shared",
			"file::memory:?cache=shared",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, applyDSNDefaults(tc.in))
		})
	}
}

// TestOpenAppliesDSNDefaults opens a database with a DSN that carries none of
// the settings and checks that the connection really has them: the string
// builder above is only useful if the driver accepts the parameters.
func TestOpenAppliesDSNDefaults(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "plain.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	var mode string
	require.NoError(t, st.DB.QueryRow("PRAGMA journal_mode").Scan(&mode))
	require.Equal(t, "wal", strings.ToLower(mode))

	var timeout int
	require.NoError(t, st.DB.QueryRow("PRAGMA busy_timeout").Scan(&timeout))
	require.Equal(t, 5000, timeout)
}
