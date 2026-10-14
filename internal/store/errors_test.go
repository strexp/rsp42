package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIsUniqueViolationUsesDriverCodes pins that constraint detection is based
// on the SQLite result code rather than on the error message: the previous
// implementation matched "UNIQUE constraint failed" / "constraint failed" as
// substrings, so any wording change would silently break the SGP.22
// "EventID not reusable" rule and the ICCID collision retry.
func TestIsUniqueViolationUsesDriverCodes(t *testing.T) {
	st, err := Open("file:" + filepath.Join(t.TempDir(), "unique.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	p := &Profile{ICCID: "89000123456789012340", State: StateAvailable}
	_, err = st.Profiles.Create(p)
	require.NoError(t, err)

	_, err = st.Profiles.Create(&Profile{ICCID: "89000123456789012340", State: StateAvailable})
	require.Error(t, err)
	require.True(t, IsUniqueViolation(err), "a duplicate ICCID is a unique violation")

	// The typed detection must survive wrapping.
	require.True(t, IsUniqueViolation(errors.Join(errors.New("context"), err)))

	require.False(t, IsUniqueViolation(nil))
	require.False(t, IsUniqueViolation(errors.New("UNIQUE constraint failed: profiles.iccid")),
		"a plain error with a matching message is not a driver constraint error")
	require.False(t, IsUniqueViolation(ErrNotFound))
}
