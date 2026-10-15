package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/rsp"
	"rsp42/internal/store"
)

func assertStatus(t *testing.T, err error, subject, reason string) {
	t.Helper()
	require.Error(t, err)
	var sc *rsp.StatusCode
	require.ErrorAs(t, err, &sc)
	require.Equal(t, subject, sc.SubjectCode, "subjectCode of %v", err)
	require.Equal(t, reason, sc.ReasonCode, "reasonCode of %v", err)
}

// F6: the ES9+ AuthenticateClient condition rows of Table 43.
func TestAuthenticateClientConditionStatusCodes(t *testing.T) {
	cmae, st := setupCMAE(t)

	// 8.1.1/3.8 "EID doesn't match the expected value".
	releasedProfile(t, st, "MATCH-EID")
	_, err := cmae.lookupProfile("MATCH-EID", "89040000000000000000000000000000")
	assertStatus(t, err, "8.1.1", "3.8")

	// 8.2.6/3.8 "MatchingID … is refused" for an unknown MatchingID.
	_, err = cmae.lookupProfile("NOPE", testEID)
	assertStatus(t, err, "8.2.6", "3.8")

	// 8.2/1.2 "Profile has not yet been released".
	p, err := NewInventory(st.Profiles, "8900012", "00101").Allocate(
		AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	p.MatchingID = "MATCH-NOT-RELEASED"
	require.NoError(t, st.Profiles.Update(p))
	_, err = cmae.lookupProfile("MATCH-NOT-RELEASED", testEID)
	assertStatus(t, err, "8.2", "1.2")
}

// F6: 8.8.5/4.10 "Time to Live Expired" for an order past its TTL.
func TestDownloadOrderTTLStatus(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.DownloadTTL = time.Nanosecond
	releasedProfile(t, st, "MATCH-TTL-CODE")

	_, err := cmae.lookupProfile("MATCH-TTL-CODE", testEID)
	assertStatus(t, err, "8.8.5", "4.10")
}

// F6: 8.8.5/6.4 "Maximum number of retries exceeded" once the download attempt
// budget is exhausted.
func TestDownloadAttemptLimitStatus(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.MaxDownloadAttempts = 1
	p := releasedProfile(t, st, "MATCH-ATT-CODE")

	require.NoError(t, cmae.registerDownloadAttempt(p))
	err := cmae.registerDownloadAttempt(p)
	assertStatus(t, err, "8.8.5", "6.4")
}

// F6: a refused Confirmation Code is 8.2.7/3.8 while retries remain and
// 8.2.7/6.4 only once the budget is exhausted (Table 40).
func TestConfirmationFailureStatus(t *testing.T) {
	cmae, st := setupCMAE(t)
	cmae.Cfg.MaxCCAttempts = 2
	p := releasedProfile(t, st, "MATCH-CC-CODE")

	first := cmae.confirmationFailureStatus(p)
	require.Equal(t, "8.2.7", first.SubjectCode)
	require.Equal(t, "3.8", first.ReasonCode)
	require.Equal(t, store.StateReleased, p.State)

	second := cmae.confirmationFailureStatus(p)
	require.Equal(t, "8.2.7", second.SubjectCode)
	require.Equal(t, "6.4", second.ReasonCode)
	require.Equal(t, store.StateError, p.State)
}

// F5: ES11 splits the cmaeCore error space: InitiateAuthentication keeps the
// Table 48a codes and AuthenticateClient uses the Table 52 codes.
func TestDSStatusMapping(t *testing.T) {
	// §5.8.1 Table 48a.
	assertStatus(t, mapDSInitiateStatus(cmErr(cmAddress, "x")), "8.9.1", "3.8")
	assertStatus(t, mapDSInitiateStatus(cmErr(cmChallenge, "x")), "8.9.1", "1.2")
	assertStatus(t, mapDSInitiateStatus(cmErr(cmBadResponse, "x")), "8.9.1", "1.2")
	assertStatus(t, mapDSInitiateStatus(cmErr(cmCI, "x")), "8.9.2", "3.1")

	// §5.8.2 Table 52. The old shared mapping sent these to 8.9.3/3.1, which
	// is Table 48a's SVN-unsupported code.
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmUnknownTxn, "x")), "8.10.1", "3.9")
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmCertChain, "x")), "8.1.3", "6.1")
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmEID, "x")), "8.1.3", "6.1")
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmSignature, "x")), "8.1", "6.1")
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmBadResponse, "x")), "8.1", "6.1")
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmTxnMismatch, "x")), "8.1", "6.1")
	assertStatus(t, mapDSAuthenticateStatus(cmErr(cmChallengeMismatch, "x")), "8.1", "6.1")

	// No event for the EventID: 8.9.5/3.9, emitted directly by the service.
	assertStatus(t, rsp.CodeEventNotFound.Status("Event not found"), "8.9.5", "3.9")
}
