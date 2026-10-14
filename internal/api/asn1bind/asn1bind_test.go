package asn1bind

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/rsp"
)

func TestSubjectCode(t *testing.T) {
	require.Equal(t, "", SubjectCode(nil))
	require.Equal(t, "", SubjectCode(errors.New("plain")))
	require.Equal(t, "8.10.1", SubjectCode(rsp.CodeUnknownTransaction.Status("x")))

	// The lookup must survive wrapping, because the service layers wrap status
	// codes with context.
	wrapped := fmt.Errorf("session lookup: %w", rsp.CodeUnknownTransaction.Status("x"))
	require.Equal(t, "8.10.1", SubjectCode(wrapped))
}

func TestCodeFor(t *testing.T) {
	table := map[string]int64{"8.10.1": 1, "8.1": 2}

	require.EqualValues(t, 1, CodeFor(rsp.CodeUnknownTransaction.Status("x"), table, 127))
	require.EqualValues(t, 2, CodeFor(rsp.CodeVerificationFailed.Status("x"), table, 127))
	// Unmapped subject and unclassified errors both fall back.
	require.EqualValues(t, 127, CodeFor(rsp.CodeEIDNotPermitted.Status("x"), table, 127))
	require.EqualValues(t, 127, CodeFor(errors.New("plain"), table, 127))
	require.EqualValues(t, 127, CodeFor(nil, table, 127))
}
