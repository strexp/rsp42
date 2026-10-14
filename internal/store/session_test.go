package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSessionEuiccVersionsRoundTrip pins N11/N12's persistence: the eUICC's
// advertised SAIP version set must survive a session reload, because the
// template compatibility check runs at GetBoundProfilePackage, after
// AuthenticateClient has returned.
func TestSessionEuiccVersionsRoundTrip(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "session.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	in := &Session{
		TransactionID:          "TXN-1",
		State:                  "authenticated",
		EID:                    "89049032000000000000000000000001",
		UPPTemplate:            "v21",
		EuiccProfileVersion:    "2.1",
		EuiccSupportedVersions: []string{"2.1", "3.2"},
		UICCCapability:         "0040",
		CreatedAt:              now,
		ExpiresAt:              now.Add(time.Hour),
	}
	require.NoError(t, st.Sessions.Put(in))

	got, err := st.Sessions.Get("TXN-1")
	require.NoError(t, err)
	require.Equal(t, "2.1", got.EuiccProfileVersion)
	require.Equal(t, []string{"2.1", "3.2"}, got.EuiccSupportedVersions)
	require.Equal(t, "0040", got.UICCCapability)
	require.Equal(t, "v21", got.UPPTemplate)

	// A session without version information stays empty (the "unknown version"
	// case the download path treats as a clean failure, not a silent pick).
	require.NoError(t, st.Sessions.Put(&Session{
		TransactionID: "TXN-2", State: "initiated", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	got, err = st.Sessions.Get("TXN-2")
	require.NoError(t, err)
	require.Empty(t, got.EuiccProfileVersion)
	require.Nil(t, got.EuiccSupportedVersions)
}
