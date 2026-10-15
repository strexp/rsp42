package asn1bind

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/rsp"
)

func TestStatusPair(t *testing.T) {
	subject, reason := StatusPair(nil)
	require.Equal(t, "", subject)
	require.Equal(t, "", reason)

	subject, reason = StatusPair(rsp.CodeUnknownTransaction.Status("x"))
	require.Equal(t, "8.10.1", subject)
	require.Equal(t, "3.9", reason)

	// The lookup must survive wrapping, because the service layers wrap status
	// codes with context.
	wrapped := fmt.Errorf("session lookup: %w", rsp.CodeUnknownTransaction.Status("x"))
	subject, reason = StatusPair(wrapped)
	require.Equal(t, "8.10.1", subject)
	require.Equal(t, "3.9", reason)
}

func TestCodeFor(t *testing.T) {
	// A slash-keyed table is the preferred form: two reason codes under one
	// subject map to different enum values (SGP.22 §6.6 error enums).
	pairTable := map[string]int64{
		"8.2.7/2.2": 2,
		"8.2.7/3.8": 3,
		"8.2.7/6.4": 4,
		"8.1":       5,
	}
	require.EqualValues(t, 2, CodeFor(rsp.Code{Subject: "8.2.7", Reason: "2.2"}.Status("x"), pairTable, 127))
	require.EqualValues(t, 3, CodeFor(rsp.Code{Subject: "8.2.7", Reason: "3.8"}.Status("x"), pairTable, 127))
	require.EqualValues(t, 4, CodeFor(rsp.Code{Subject: "8.2.7", Reason: "6.4"}.Status("x"), pairTable, 127))
	// A pair miss falls back to the subject-only entry.
	require.EqualValues(t, 5, CodeFor(rsp.Code{Subject: "8.1", Reason: "6.1"}.Status("x"), pairTable, 127))
	// Unmapped subject and unclassified errors both fall back.
	require.EqualValues(t, 127, CodeFor(rsp.CodeEIDMismatch.Status("x"), pairTable, 127))
	require.EqualValues(t, 127, CodeFor(errors.New("plain"), pairTable, 127))
	require.EqualValues(t, 127, CodeFor(nil, pairTable, 127))

	// A legacy subject-only table keeps working.
	subjectTable := map[string]int64{"8.10.1": 1, "8.1": 2}
	require.EqualValues(t, 1, CodeFor(rsp.CodeUnknownTransaction.Status("x"), subjectTable, 127))
	require.EqualValues(t, 2, CodeFor(rsp.CodeVerificationFailed.Status("x"), subjectTable, 127))
	require.EqualValues(t, 127, CodeFor(rsp.CodeEIDMismatch.Status("x"), subjectTable, 127))
}
