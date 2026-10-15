package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/client/es12"
	"rsp42/internal/saipver"
	"rsp42/internal/store"
)

// TestResolveUPPTemplateViaFakes drives the template resolution through the
// consumer-defined interfaces only: no database, no config, no certificate
// manager (TODO.md §3.5, DIP regression).
func TestResolveUPPTemplateViaFakes(t *testing.T) {
	upp := newFakeUPPStore(
		&store.UPPTemplate{Name: "v21", SAIPMajor: 2, SAIPMinor: 1, Active: true},
		&store.UPPTemplate{Name: "v23", SAIPMajor: 2, SAIPMinor: 3, Active: true},
		&store.UPPTemplate{Name: "tenant-def", TenantID: "carrier-a", SAIPMajor: 2, SAIPMinor: 0, Active: true},
		&store.UPPTemplate{Name: "global", SAIPMajor: 1, SAIPMinor: 0, Active: true},
	)
	cmae := &CMAE{Deps: CMAEDeps{
		UPP:        upp,
		DefaultUPP: "global",
		Tenants: fakeTenantLookup{
			defaultUPP: map[string]string{"carrier-a": "tenant-def"},
		},
		Personalization: newFakePersoResolver(),
	}}
	profile := &store.Profile{TenantID: "carrier-a", ICCID: "89000123456789012341"}

	// An unknown version set never picks a template, and the registry is not
	// even consulted.
	_, err := cmae.resolveUPPTemplate(profile, &store.Session{})
	var vErr *ErrProfileVersionNotSupported
	require.ErrorAs(t, err, &vErr)
	require.Zero(t, upp.Selects)

	// The best template the version set supports wins.
	tpl, err := cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"2.3"}})
	require.NoError(t, err)
	require.Equal(t, "v23", tpl.Name)

	// With nothing version-compatible, the tenant default is used.
	tpl, err = cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"2.0"}})
	require.NoError(t, err)
	require.Equal(t, "tenant-def", tpl.Name)

	// Below every template the tenant default cannot help either: a clean
	// version failure naming the lowest considered version.
	_, err = cmae.resolveUPPTemplate(profile, &store.Session{EuiccSupportedVersions: []string{"0.9"}})
	require.ErrorAs(t, err, &vErr)
	require.Equal(t, []string{"0.9"}, vErr.SupportedVersions)
	require.Equal(t, "1.0", vErr.LowestTemplateVersion)

	// A pinned order template is authoritative: it is neither substituted nor
	// bypassed.
	pinned := &store.Profile{TenantID: "carrier-a", ICCID: profile.ICCID, UPPTemplate: "v23"}
	_, err = cmae.resolveUPPTemplate(pinned, &store.Session{EuiccSupportedVersions: []string{"2.1"}})
	require.ErrorAs(t, err, &vErr)
	require.Equal(t, "2.3", vErr.LowestTemplateVersion)
}

// TestLoadUPPViaFakes exercises the personalization path through the
// PersonalizationResolver interface and verifies the resolver is consulted.
func TestLoadUPPViaFakes(t *testing.T) {
	upp := newFakeUPPStore(&store.UPPTemplate{
		Name: "v21", SAIPMajor: 2, SAIPMinor: 1, Active: true,
		Bytes: minimalUPPBytes(),
	})
	perso := newFakePersoResolver()
	perso.byKey["/"+testICCID] = nil // no per-ICCID record: the resolver is still called
	cmae := &CMAE{Deps: CMAEDeps{
		UPP:             upp,
		DefaultUPP:      "v21",
		Personalization: perso,
	}}
	profile := &store.Profile{ICCID: testICCID}
	raw, err := cmae.loadUPP(profile, &store.Session{EuiccSupportedVersions: []string{"2.1"}})
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.Equal(t, 1, perso.Calls)
}

const testICCID = "89000123456789012341"

// minimalUPPBytes builds a syntactically valid minimal profile: a ProfileHeader
// (major 2, minor 1) followed by PE-MF and PE-End.
func minimalUPPBytes() []byte {
	return []byte{
		0xa0, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0x01, // header
		0xb0, 0x00, // mf
		0xaa, 0x00, // end
	}
}

// TestOrderServiceTransitionsViaFakeStore pins the lifecycle through the
// ProfileStore interface, including the invalid-transition error.
func TestOrderServiceTransitionsViaFakeStore(t *testing.T) {
	profile := &store.Profile{ICCID: testICCID, State: store.StateAllocated}
	repo := newFakeProfileStore(profile)
	orders := NewOrderService(repo)

	got, err := orders.Confirm(testICCID, false)
	require.NoError(t, err)
	require.Equal(t, store.StateConfirmed, got.State)
	require.Equal(t, 1, repo.Updates)

	got, err = orders.Release(testICCID)
	require.NoError(t, err)
	require.Equal(t, store.StateReleased, got.State)

	// Released -> Confirmed is not a permitted transition.
	_, err = orders.Confirm(testICCID, false)
	var te *TransitionError
	require.ErrorAs(t, err, &te)

	// An unknown ICCID surfaces the repository's ErrNotFound unchanged.
	_, err = orders.Release("89000123456789099999")
	require.ErrorIs(t, err, store.ErrNotFound)

	// A persistence failure is propagated rather than swallowed.
	repo.FailUpd = errors.New("disk on fire")
	other := &store.Profile{ICCID: "89000123456789012358", State: store.StateAllocated}
	repo.put(other)
	_, err = NewOrderService(repo).Confirm(other.ICCID, false)
	require.ErrorContains(t, err, "disk on fire")
}

// TestInventoryResendViaFakeStore pins the Table 24 graceful resend and the
// quota sentinel through the ProfileCreator/ICCIDPool interfaces.
func TestInventoryResendViaFakeStore(t *testing.T) {
	existing := &store.Profile{
		ICCID: testICCID, TenantID: "carrier-a", ProfileType: "operational",
		EID: "89049032000000000000000000000001", State: store.StateAllocated,
	}
	repo := newFakeProfileStore(existing)
	inv := NewInventory(repo, "8900012", "00101")

	// Same order again: the existing profile is returned, nothing is created.
	got, err := inv.Allocate(AllocateRequest{
		ICCID: testICCID, Tenant: "carrier-a", ProfileType: "operational",
		EID: "89049032000000000000000000000001",
	})
	require.NoError(t, err)
	require.Equal(t, testICCID, got.ICCID)
	require.Zero(t, repo.Creates)

	// A different profile type is a conflict (8.2.1/3.3 at the ES2+ layer).
	_, err = inv.Allocate(AllocateRequest{ICCID: testICCID, Tenant: "carrier-a", ProfileType: "other"})
	require.ErrorIs(t, err, ErrICCIDInUse)

	// Quota exhaustion uses the specific sentinel.
	zero := 0
	quotaInv := NewInventory(repo, "8900012", "00101")
	quotaInv.ProfileQuota = func(tenant string) (*int, error) { return &zero, nil }
	quotaInv.CountProfiles = func(tenant string) (int, error) { return 0, nil }
	_, err = quotaInv.Allocate(AllocateRequest{Tenant: "carrier-a", ProfileType: "operational"})
	require.ErrorIs(t, err, ErrQuotaExceeded)
}

// TestInventoryPoolViaFakeStore pins the pooled allocation path and the
// rollback-free success path through the ICCIDPool interface.
func TestInventoryPoolViaFakeStore(t *testing.T) {
	pool := newFakeICCIDPool("89000123456789012347")
	repo := newFakeProfileStore()
	inv := NewInventory(repo, "8900012", "00101")
	inv.Pool = pool

	got, err := inv.Allocate(AllocateRequest{Tenant: "carrier-a", ProfileType: "operational"})
	require.NoError(t, err)
	require.Equal(t, "89000123456789012347", got.ICCID)
	require.Equal(t, 1, pool.Reserves)
	require.Equal(t, "allocated", pool.state[got.ICCID])
	require.Equal(t, 1, repo.Creates)
}

// TestInventoryClaimFailureRollsBackProfile pins the pool consistency fix: a
// failed claim must not leave a profile row behind, otherwise the reservation
// lapses and ReleaseExpired hands the same ICCID out again while the profile
// still references it.
func TestInventoryClaimFailureRollsBackProfile(t *testing.T) {
	const iccid = "89000123456789012348"
	pool := newFakeICCIDPool(iccid)
	pool.FailClaim = errors.New("pool is on fire")
	repo := newFakeProfileStore()
	inv := NewInventory(repo, "8900012", "00101")
	inv.Pool = pool

	_, err := inv.Allocate(AllocateRequest{Tenant: "carrier-a", ProfileType: "operational"})
	require.ErrorContains(t, err, "pool is on fire")
	require.Equal(t, 1, repo.Deletes, "the profile row must be rolled back when the claim fails")
	require.Zero(t, len(repo.byICCID), "no profile may reference an unclaimed ICCID")
}

// TestInventoryReserveReleaseFailureSurfaces pins that a failed release of an
// unusable reservation is reported instead of silently leaking the ICCID.
func TestInventoryReserveReleaseFailureSurfaces(t *testing.T) {
	const iccid = "89000123456789012349"
	pool := newFakeICCIDPool(iccid)
	pool.FailSetState = errors.New("state write failed")
	repo := newFakeProfileStore()
	repo.FailNew = errors.New("insert failed")
	inv := NewInventory(repo, "8900012", "00101")
	inv.Pool = pool

	_, err := inv.Allocate(AllocateRequest{Tenant: "carrier-a", ProfileType: "operational"})
	require.ErrorContains(t, err, "state write failed")
}

// TestVersionHelpersViaFakes is a guard on the interface shape used above: the
// resolution API takes a version set, not a scalar (N11 reservation).
func TestVersionHelpersViaFakes(t *testing.T) {
	var _ UPPStore = (*fakeUPPStore)(nil)
	var _ ProfileStore = (*fakeProfileStore)(nil)
	var _ ProfileCreator = (*fakeProfileStore)(nil)
	var _ TenantLookup = fakeTenantLookup{}
	var _ PersonalizationResolver = (*fakePersoResolver)(nil)
	var _ ICCIDPool = (*fakeICCIDPool)(nil)
	var _ ICCIDRecycler = (*fakeICCIDPool)(nil)

	require.Equal(t, -1, saipver.Version{Major: 2, Minor: 1}.Compare(saipver.Version{Major: 2, Minor: 2}))
}

// TestEventServiceStorageErrorsAreNotNotFound pins the sentinel handling in the
// SM-DS event service: a storage failure must not be reported as "EventID free"
// (Register) or as "event not found" (Delete).
func TestEventServiceStorageErrorsAreNotNotFound(t *testing.T) {
	var _ EventStore = (*fakeEventStore)(nil)

	boom := errors.New("disk on fire")
	repo := newFakeEventStore()
	repo.FailGet = boom
	svc := NewEventService(repo, "root", "ds.example.com", time.Hour)

	err := svc.Register("89049032000000000000000000000001", "dp.example.com", "E1", false, "2.999.10", es12.EventMeta{})
	require.ErrorIs(t, err, boom, "a storage failure must not be answered as EventIDInUse")
	require.NotErrorIs(t, err, ErrEventIDInUse)

	err = svc.Delete("89049032000000000000000000000001", "E1", "2.999.10")
	require.ErrorIs(t, err, boom, "a storage failure must not be answered as not found")
	require.NotErrorIs(t, err, ErrEventNotFound)

	// A genuinely missing event is still reported as not found.
	repo.FailGet = nil
	err = svc.Delete("89049032000000000000000000000001", "E1", "2.999.10")
	require.ErrorIs(t, err, ErrEventNotFound)
}
