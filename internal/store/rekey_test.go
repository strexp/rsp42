package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/kms"
)

// The KMS file provider must satisfy the persistence layer's sealing seam.
var _ Sealer = (*kms.FileProvider)(nil)

// seal returns plaintext sealed with provider, the way the service layer stores
// the sensitive columns.
func seal(t *testing.T, provider Sealer, plaintext string) []byte {
	t.Helper()
	ct, err := provider.Encrypt([]byte(plaintext))
	require.NoError(t, err)
	return ct
}

func testProvider(t *testing.T, hexKey string) *kms.FileProvider {
	t.Helper()
	p, err := kms.NewFileProviderFromHex(hexKey)
	require.NoError(t, err)
	return p
}

// newRekeyStore opens a store with one session and one personalization row whose
// secret columns are sealed with oldKEK.
func newRekeyStore(t *testing.T, oldKEK Sealer) *Store {
	t.Helper()
	st, err := Open("file:" + filepath.Join(t.TempDir(), "rekey.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	require.NoError(t, st.Sessions.Put(&Session{
		TransactionID:   "txn-1",
		State:           "authenticated",
		ServerChallenge: seal(t, oldKEK, "server-challenge"),
		SmdpOtSK:        seal(t, oldKEK, "smdp-ot-sk"),
		SharedSecret:    seal(t, oldKEK, "shared-secret"),
		CCHash:          seal(t, oldKEK, "cc-hash"),
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	}))
	require.NoError(t, st.Perso.Upsert(&Personalization{
		ICCID: "8900012345678901234",
		K:     seal(t, oldKEK, "ki-material"),
		OPc:   seal(t, oldKEK, "opc-material"),
	}))
	return st
}

// requireSealedWith asserts that value is openable by want and by no one else.
func requireSealedWith(t *testing.T, value []byte, want Sealer, not Sealer) {
	t.Helper()
	_, err := want.Decrypt(value)
	require.NoError(t, err, "value must be sealed with the expected KEK")
	if not != nil {
		_, err = not.Decrypt(value)
		require.Error(t, err, "value must not still be sealed with the old KEK")
	}
}

func TestRekeyRotatesSessionsAndPersonalization(t *testing.T) {
	oldKEK := testProvider(t, strings.Repeat("11", 32))
	newKEK := testProvider(t, strings.Repeat("22", 32))
	st := newRekeyStore(t, oldKEK)

	res, err := st.Rekey(oldKEK, newKEK)
	require.NoError(t, err)
	// Four session columns plus K and OPc.
	require.Equal(t, 6, res.Rotated)
	require.Zero(t, res.Current)
	require.Zero(t, res.Empty)

	sess, err := st.Sessions.Get("txn-1")
	require.NoError(t, err)
	requireSealedWith(t, sess.ServerChallenge, newKEK, oldKEK)
	requireSealedWith(t, sess.SmdpOtSK, newKEK, oldKEK)
	requireSealedWith(t, sess.SharedSecret, newKEK, oldKEK)
	requireSealedWith(t, sess.CCHash, newKEK, oldKEK)

	perso, err := st.Perso.GetByICCID("", "8900012345678901234")
	require.NoError(t, err)
	requireSealedWith(t, perso.K, newKEK, oldKEK)
	requireSealedWith(t, perso.OPc, newKEK, oldKEK)
}

// TestRekeyIsResumable pins the property an interrupted rotation relies on: a
// second run is a no-op rather than an error.
func TestRekeyIsResumable(t *testing.T) {
	oldKEK := testProvider(t, strings.Repeat("11", 32))
	newKEK := testProvider(t, strings.Repeat("22", 32))
	st := newRekeyStore(t, oldKEK)

	first, err := st.Rekey(oldKEK, newKEK)
	require.NoError(t, err)
	require.Equal(t, 6, first.Rotated)

	second, err := st.Rekey(oldKEK, newKEK)
	require.NoError(t, err)
	require.Zero(t, second.Rotated, "a resumed run must not re-encrypt")
	require.Equal(t, 6, second.Current, "already-rotated values are reported as current")
}

// TestRekeyRejectsForeignKeyAndRollsBack pins the failure contract: a value that
// neither key opens aborts the table, leaving its other rows untouched.
func TestRekeyRejectsForeignKeyAndRollsBack(t *testing.T) {
	oldKEK := testProvider(t, strings.Repeat("11", 32))
	newKEK := testProvider(t, strings.Repeat("22", 32))
	thirdKEK := testProvider(t, strings.Repeat("33", 32))
	st := newRekeyStore(t, oldKEK)

	// A second personalization row sealed with a key that is neither the old nor
	// the new one (e.g. a row written after a partially rolled-back rotation).
	require.NoError(t, st.Perso.Upsert(&Personalization{
		ICCID: "8900012345678901235",
		K:     seal(t, thirdKEK, "foreign"),
	}))

	_, err := st.Rekey(oldKEK, newKEK)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not sealed with the current KEK")

	// The personalization table rolled back: both rows are still old/foreign.
	perso, err := st.Perso.GetByICCID("", "8900012345678901234")
	require.NoError(t, err)
	requireSealedWith(t, perso.K, oldKEK, nil)

	// The sessions table was committed before the personalization failure, so it
	// holds the new KEK; that is why re-running is what completes a rotation.
	sess, err := st.Sessions.Get("txn-1")
	require.NoError(t, err)
	requireSealedWith(t, sess.SharedSecret, newKEK, oldKEK)
}

// TestRekeyEmptyColumnsDoNothing pins that NULL/zero-length values are counted,
// not treated as ciphertext to open.
func TestRekeyEmptyColumnsDoNothing(t *testing.T) {
	oldKEK := testProvider(t, strings.Repeat("11", 32))
	newKEK := testProvider(t, strings.Repeat("22", 32))

	st, err := Open("file:" + filepath.Join(t.TempDir(), "empty.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now().UTC()
	require.NoError(t, st.Sessions.Put(&Session{
		TransactionID: "txn-empty", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	res, err := st.Rekey(oldKEK, newKEK)
	require.NoError(t, err)
	require.Zero(t, res.Rotated)
	require.Equal(t, 4, res.Empty)
}
