package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/kms"
	"rsp42/internal/store"
)

func TestCanTransitionMatrix(t *testing.T) {
	legal := []struct{ from, to store.ProfileState }{
		{store.StateAvailable, store.StateAllocated},
		{store.StateAvailable, store.StateLinked},
		{store.StateAllocated, store.StateConfirmed},
		{store.StateAllocated, store.StateReleased},
		{store.StateLinked, store.StateConfirmed},
		{store.StateConfirmed, store.StateReleased},
		{store.StateReleased, store.StateDownloaded},
		{store.StateDownloaded, store.StateInstalled},
		{store.StateDownloaded, store.StateError},
		{store.StateError, store.StateAvailable},
		{store.StateReleased, store.StateError},
		{store.StateDownloaded, store.StateAvailable},
		{store.StateConfirmed, store.StateUnavailable},
		{store.StateReleased, store.StateDownloaded}, // retry
	}
	for _, c := range legal {
		require.True(t, CanTransition(c.from, c.to), "%s -> %s should be legal", c.from, c.to)
	}

	illegal := []struct{ from, to store.ProfileState }{
		{store.StateAvailable, store.StateInstalled},
		{store.StateAvailable, store.StateConfirmed},
		{store.StateConfirmed, store.StateDownloaded},
		{store.StateInstalled, store.StateInstalled},
		{store.StateInstalled, store.StateDownloaded},
		{store.StateUnavailable, store.StateAllocated},
	}
	for _, c := range illegal {
		if c.from == c.to {
			continue
		}
		require.False(t, CanTransition(c.from, c.to), "%s -> %s should be illegal", c.from, c.to)
	}

	// Same-state is always idempotent.
	require.True(t, CanTransition(store.StateConfirmed, store.StateConfirmed))
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOrderServiceLifecycle(t *testing.T) {
	s := newTestStore(t)
	svc := NewOrderService(s.Profiles)

	_, err := s.Profiles.Create(&store.Profile{ICCID: "89000123456789012340", State: store.StateAvailable})
	require.NoError(t, err)

	p, err := svc.Link("89000123456789012340")
	require.NoError(t, err)
	require.Equal(t, store.StateLinked, p.State)

	p, err = svc.Confirm("89000123456789012340", true)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, p.State)
	require.True(t, p.ReleaseFlag)

	// Idempotent confirm.
	p, err = svc.Confirm("89000123456789012340", true)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, p.State)

	p, err = svc.MarkDownloaded("89000123456789012340")
	require.NoError(t, err)
	require.Equal(t, store.StateDownloaded, p.State)
	require.Equal(t, 1, p.DownloadAttempts)

	p, err = svc.MarkInstalled("89000123456789012340")
	require.NoError(t, err)
	require.Equal(t, store.StateInstalled, p.State)
	require.NotNil(t, p.InstalledAt)

	// Illegal: Installed -> Downloaded.
	_, err = svc.MarkDownloaded("89000123456789012340")
	require.Error(t, err)
}

func TestSessionEncryptionAtRest(t *testing.T) {
	s := newTestStore(t)
	provider, err := kms.NewFileProviderFromKEK(make([]byte, 32))
	require.NoError(t, err)
	ss := NewSessionService(s.Sessions, provider, 0)

	secret := []byte("0123456789abcdef")
	require.NoError(t, ss.Put(&store.Session{
		TransactionID:   "TXN1",
		State:           "initiated",
		ServerChallenge: secret,
		SharedSecret:    secret,
		SmdpOtSK:        secret,
	}))

	// The raw database column must not contain the plaintext.
	var raw []byte
	require.NoError(t, s.DB.QueryRow("SELECT server_challenge FROM sessions WHERE transaction_id='TXN1'").Scan(&raw))
	require.NotEqual(t, secret, raw)

	got, err := ss.Get("TXN1")
	require.NoError(t, err)
	require.Equal(t, secret, got.ServerChallenge)
	require.Equal(t, secret, got.SharedSecret)
	require.Equal(t, secret, got.SmdpOtSK)
}

func TestEventRepoReuseForbidden(t *testing.T) {
	s := newTestStore(t)
	rec := &store.EventRecord{EID: "89049032123451234512345678901235", EventID: "E1", RSPServerAddress: "dp", CallerOID: "2.999.10"}
	_, err := s.Events.Insert(rec)
	require.NoError(t, err)

	// Same triple again is rejected (EventID not reusable).
	_, err = s.Events.Insert(&store.EventRecord{EID: rec.EID, EventID: "E1", RSPServerAddress: "dp", CallerOID: "2.999.10"})
	require.ErrorIs(t, err, store.ErrEventIDInUse)

	// Even after soft delete it stays reserved.
	ok, err := s.Events.SoftDelete(rec.ID)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = s.Events.Insert(&store.EventRecord{EID: rec.EID, EventID: "E1", RSPServerAddress: "dp", CallerOID: "2.999.10"})
	require.ErrorIs(t, err, store.ErrEventIDInUse)

	// Another caller may use the same EventID.
	_, err = s.Events.Insert(&store.EventRecord{EID: rec.EID, EventID: "E1", RSPServerAddress: "dp2", CallerOID: "2.999.11"})
	require.NoError(t, err)
}

// seedLinkedProfile creates an Available profile and drives it to Linked.
func seedLinkedProfile(t *testing.T, s *store.Store, svc *OrderService, iccid string) {
	t.Helper()
	_, err := s.Profiles.Create(&store.Profile{ICCID: iccid, State: store.StateAvailable})
	require.NoError(t, err)
	_, err = svc.Link(iccid)
	require.NoError(t, err)
}

// TestTransitionResendAppliesMutate is the regression test for the idempotent
// branch that returned before running mutate: a duplicate installation
// notification must still record the failure reason, and the change must be
// persisted rather than only applied to the in-memory copy.
func TestTransitionResendAppliesMutate(t *testing.T) {
	s := newTestStore(t)
	svc := NewOrderService(s.Profiles)
	const iccid = "89000123456789012341"
	seedLinkedProfile(t, s, svc, iccid)

	_, err := svc.Confirm(iccid, true)
	require.NoError(t, err)

	p, err := svc.MarkError(iccid, "first failure")
	require.NoError(t, err)
	require.Equal(t, store.StateError, p.State)
	require.Equal(t, "first failure", p.ErrorReason)

	// Resend: Error -> Error is a legal no-op, but the reason must be refreshed.
	p, err = svc.MarkError(iccid, "second failure")
	require.NoError(t, err)
	require.Equal(t, store.StateError, p.State)
	require.Equal(t, "second failure", p.ErrorReason)

	got, err := s.Profiles.GetByICCID(iccid)
	require.NoError(t, err)
	require.Equal(t, "second failure", got.ErrorReason, "resend mutation must be persisted")
}

// TestTransitionResendKeepsInstalledAt pins that a duplicate installation
// notification does not move the installation timestamp.
func TestTransitionResendKeepsInstalledAt(t *testing.T) {
	s := newTestStore(t)
	svc := NewOrderService(s.Profiles)
	const iccid = "89000123456789012342"
	seedLinkedProfile(t, s, svc, iccid)

	_, err := svc.Confirm(iccid, true)
	require.NoError(t, err)
	_, err = svc.MarkDownloaded(iccid)
	require.NoError(t, err)

	first, err := svc.MarkInstalled(iccid)
	require.NoError(t, err)
	require.NotNil(t, first.InstalledAt)

	// Pin a distinctive past timestamp so that "unchanged" is unambiguous even
	// though SQLite stores whole seconds.
	loaded, err := s.Profiles.GetByICCID(iccid)
	require.NoError(t, err)
	past := time.Unix(1_000_000_000, 0).UTC()
	loaded.InstalledAt = &past
	require.NoError(t, s.Profiles.Update(loaded))

	again, err := svc.MarkInstalled(iccid)
	require.NoError(t, err)
	require.NotNil(t, again.InstalledAt)
	require.Equal(t, past.Unix(), again.InstalledAt.Unix(),
		"a duplicate notification must not move InstalledAt")
}

// TestTransitionAttemptCounterOnlyOnStateChange pins that the download attempt
// counter is advanced by a real transition only; the counter is owned by
// CMAE.registerDownloadAttempt.
func TestTransitionAttemptCounterOnlyOnStateChange(t *testing.T) {
	s := newTestStore(t)
	svc := NewOrderService(s.Profiles)
	const iccid = "89000123456789012343"
	seedLinkedProfile(t, s, svc, iccid)

	_, err := svc.Confirm(iccid, true)
	require.NoError(t, err)

	p, err := svc.MarkDownloaded(iccid)
	require.NoError(t, err)
	require.Equal(t, 1, p.DownloadAttempts)

	// Downloaded -> Downloaded is a legal no-op and must not inflate the counter.
	p, err = svc.MarkDownloaded(iccid)
	require.NoError(t, err)
	require.Equal(t, 1, p.DownloadAttempts)
}

// TestInstalledCanBeReleased pins SGP.22 §3.1.7: the SM-DP+ lets a Profile whose
// Activation Code was retrieved by ACR-0 be redownloaded after the associated
// Delete Notification, and rsp42 models "downloadable again" as Released.
func TestInstalledCanBeReleased(t *testing.T) {
	require.True(t, CanTransition(store.StateInstalled, store.StateReleased))
	require.NoError(t, AssertTransition(store.StateInstalled, store.StateReleased))

	_, st := setupCMAE(t)
	orders := NewOrderService(st.Profiles)
	profile, err := NewInventory(st.Profiles, "8900012", "00101").
		Allocate(AllocateRequest{EID: testEID, ProfileType: "operational"})
	require.NoError(t, err)
	_, err = orders.Confirm(profile.ICCID, true)
	require.NoError(t, err)
	_, err = orders.MarkDownloaded(profile.ICCID)
	require.NoError(t, err)
	_, err = orders.MarkInstalled(profile.ICCID)
	require.NoError(t, err)

	got, err := orders.Release(profile.ICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, got.State)
}
