package service

import (
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/rsp/status"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

// F1 regression: the JSON binding carries the bare ES10b BF41
// CancelSessionResponse (SGP.22 §6.5.2.10: "CancelSessionResponse data object
// defined in Section 5.7.14"), not the §6.6.2.5 CancelSessionRequestEs9 wrapper.
// Decoding it with the wrapper decoder left the transactionId empty, so every
// JSON call failed with 8.10.1/3.9 "transactionId mismatch".
func TestCancelSessionJSONBareResponse(t *testing.T) {
	cmae, st := setupCMAE(t)
	profile := releasedProfile(t, st, "")

	const txn = "000102030405060708090A0B0C0D0E0F"
	require.NoError(t, cmae.Deps.Sessions.Put(&store.Session{
		TransactionID: txn, State: "authenticated", ProfileID: profile.ID,
	}))

	// Real BF41 CancelSessionResponse vector (testdata/vectors/rsp_golden.json):
	// cancelSessionResponseOk { euiccCancelSessionSigned { transactionId
	// 000102…0E0F, smdpOid 2.999.10, reason endUserRejection(0) }, signature }.
	raw := testutil.MustHex(t, "bf4161a05f301a8010000102030405060708090a0b0c0d0e0f810388370a8201005f374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

	got, reason, err := cmae.CancelSessionJSON(txn, raw)
	require.NoError(t, err, "the bare ES10b response must decode and match the transactionId")
	require.Equal(t, txn, got)
	require.EqualValues(t, 0, reason)

	// endUserRejection(0) terminates the order: the released Profile moves to
	// Error and the session is discarded.
	after, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateError, after.State)
	_, err = cmae.Deps.Sessions.Get(txn)
	require.Error(t, err)
}

// The ES10b error alternative (invalidTransactionId(5), §5.7.14) maps to the
// ES9+ 8.10.1/3.9 rather than being mistaken for a usable session.
func TestCancelSessionJSONErrorAlternative(t *testing.T) {
	cmae, st := setupCMAE(t)
	profile := releasedProfile(t, st, "")
	const txn = "000102030405060708090A0B0C0D0E0F"
	require.NoError(t, cmae.Deps.Sessions.Put(&store.Session{
		TransactionID: txn, State: "authenticated", ProfileID: profile.ID,
	}))

	// cancelSessionResponseError { invalidTransactionId(5) }.
	raw := testutil.MustHex(t, "bf4103810105")
	_, _, err := cmae.CancelSessionJSON(txn, raw)
	require.Error(t, err)
	var sc *status.StatusCode
	require.ErrorAs(t, err, &sc)
	require.Equal(t, "8.10.1", sc.SubjectCode)
	require.Equal(t, "3.9", sc.ReasonCode)
}

// The ASN.1 binding keeps using the §6.6.2.5 wrapper decoder.
func TestCancelSessionASN1Wrapper(t *testing.T) {
	cmae, st := setupCMAE(t)
	profile := releasedProfile(t, st, "")

	const txn = "000102030405060708090A0B0C0D0E0F"
	require.NoError(t, cmae.Deps.Sessions.Put(&store.Session{
		TransactionID: txn, State: "authenticated", ProfileID: profile.ID,
	}))

	// Golden CancelSessionRequestEs9: wrapper transactionId 000102…0E0F and an
	// embedded ES10b CancelSessionResponse carrying reason
	// loadBppExecutionError(5).
	raw := testutil.MustHex(t, "bf411a8010000102030405060708090a0b0c0d0e0fa106bf4103810105")

	got, reason, err := cmae.CancelSession(txn, raw)
	require.NoError(t, err)
	require.Equal(t, txn, got)
	require.EqualValues(t, 5, reason)

	after, err := st.Profiles.GetByICCID(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateError, after.State)
}
