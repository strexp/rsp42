package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/saipver"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open("file:" + filepath.Join(t.TempDir(), "tenant.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestTenantCRUD(t *testing.T) {
	st := openTestStore(t)
	quota := 2

	require.NoError(t, st.Tenants.Upsert(&Tenant{
		ID: "carrier-a", Name: "Carrier A", ProfileQuota: &quota, DefaultUPP: "default", CallbackURL: "https://a.example/cb",
	}))
	got, err := st.Tenants.Get("carrier-a")
	require.NoError(t, err)
	require.Equal(t, "Carrier A", got.Name)
	require.Equal(t, TenantActive, got.Status)
	require.NotNil(t, got.ProfileQuota)
	require.Equal(t, 2, *got.ProfileQuota)

	def, err := st.Tenants.DefaultUPPForTenant("carrier-a")
	require.NoError(t, err)
	require.Equal(t, "default", def)

	// Upsert is a full replace that preserves created_at.
	created := got.CreatedAt
	require.NoError(t, st.Tenants.Upsert(&Tenant{ID: "carrier-a", Name: "Carrier A2", DefaultUPP: "other"}))
	got, err = st.Tenants.Get("carrier-a")
	require.NoError(t, err)
	require.Equal(t, "Carrier A2", got.Name)
	require.Equal(t, "other", got.DefaultUPP)
	require.Equal(t, created.Unix(), got.CreatedAt.Unix())

	// Unknown tenants degrade gracefully.
	def, err = st.Tenants.DefaultUPPForTenant("nobody")
	require.NoError(t, err)
	require.Empty(t, def)
	cb, err := st.Tenants.CallbackURLForTenant("nobody")
	require.NoError(t, err)
	require.Empty(t, cb)

	require.NoError(t, st.Tenants.Delete("carrier-a"))
	require.ErrorIs(t, st.Tenants.Delete("carrier-a"), ErrNotFound)
}

func TestUPPTemplateNamesAreUniquePerTenant(t *testing.T) {
	st := openTestStore(t)

	tpl := func(tenant, name string, major int) *UPPTemplate {
		return &UPPTemplate{Name: name, TenantID: tenant, SAIPMajor: major, SHA256: name, Bytes: []byte{1}, Active: true}
	}
	// Two tenants may each own a template called "default"; a global "default"
	// may exist alongside them.
	require.NoError(t, st.UPP.Upsert(tpl("carrier-a", "default", 2)))
	require.NoError(t, st.UPP.Upsert(tpl("carrier-b", "default", 2)))
	require.NoError(t, st.UPP.Upsert(tpl("", "default", 2)))

	// Upsert replaces within a scope rather than inserting a duplicate.
	require.NoError(t, st.UPP.Upsert(tpl("", "default", 3)))
	global, err := st.UPP.GetScoped("", "default")
	require.NoError(t, err)
	require.Equal(t, 3, global.SAIPMajor)

	// A raw insert that bypasses the upsert path is rejected by the unique
	// index, proving the constraint is (tenant, name).
	_, err = st.DB.Exec(`INSERT INTO upp_templates (name, tenant_id, saip_major, saip_minor, sha256, bytes, active, created_at, updated_at)
		VALUES ('default','carrier-a',1,0,'x',X'01',1,0,0)`)
	require.Error(t, err)

	a, err := st.UPP.GetScoped("carrier-a", "default")
	require.NoError(t, err)
	require.Equal(t, "carrier-a", a.TenantID)

	// GetForTenant prefers the tenant's own template, then the global one.
	own, err := st.UPP.GetForTenant("carrier-a", "default")
	require.NoError(t, err)
	require.Equal(t, "carrier-a", own.TenantID)
	fallback, err := st.UPP.GetForTenant("carrier-c", "default")
	require.NoError(t, err)
	require.Equal(t, "", fallback.TenantID)

	// Replacing within a scope updates in place.
	require.NoError(t, st.UPP.Upsert(tpl("carrier-a", "default", 3)))
	own, err = st.UPP.GetScoped("carrier-a", "default")
	require.NoError(t, err)
	require.Equal(t, 3, own.SAIPMajor)

	// SelectBestFor honours the tenant scope and version ceiling.
	require.NoError(t, st.UPP.Upsert(&UPPTemplate{Name: "v21", TenantID: "carrier-a", SAIPMajor: 2, SAIPMinor: 1, SHA256: "x", Bytes: []byte{1}, Active: true}))
	best, err := st.UPP.SelectBestFor("carrier-a", []saipver.Version{{Major: 2, Minor: 1}})
	require.NoError(t, err)
	require.Equal(t, "v21", best.Name)

	list, err := st.UPP.ListForTenant("carrier-a")
	require.NoError(t, err)
	require.Len(t, list, 3) // own two + global default

	count, err := st.UPP.CountForTenant("carrier-a")
	require.NoError(t, err)
	require.Equal(t, 2, count)

	require.NoError(t, st.UPP.Delete("carrier-a", "default"))
	require.ErrorIs(t, st.UPP.Delete("carrier-a", "default"), ErrNotFound)
}

func TestICCIDPoolTenantIsolationAndReservationTTL(t *testing.T) {
	st := openTestStore(t)

	_, insA, _, err := st.Pool.ImportRange("carrier-a", "8900012000000000000", "8900012000000000099", "a")
	require.NoError(t, err)
	require.Greater(t, insA, 0)
	_, insB, _, err := st.Pool.ImportRange("carrier-b", "8900022000000000000", "8900022000000000099", "b")
	require.NoError(t, err)
	require.Greater(t, insB, 0)

	// A reservation never crosses tenants.
	iccidA, err := st.Pool.Reserve("carrier-a", "EID-A", "order-a", time.Hour)
	require.NoError(t, err)
	require.True(t, len(iccidA) >= 7 && iccidA[:7] == "8900012", "got %s", iccidA)

	iccidB, err := st.Pool.Reserve("carrier-b", "", "", 0)
	require.NoError(t, err)
	require.Equal(t, "8900022", iccidB[:7])

	// The reserved entry records its reference and deadline.
	entries, total, err := st.Pool.ListPage("allocated", "", ptr("carrier-a"), 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, "order-a", entries[0].Reference)
	require.NotNil(t, entries[0].ReservedUntil)

	// Claim clears the deadline; an entry with a deadline in the past is
	// reclaimed by the GC.
	require.NoError(t, st.Pool.Claim(iccidA, 42))
	entries, _, err = st.Pool.ListPage("allocated", "", ptr("carrier-a"), 10, 0)
	require.NoError(t, err)
	require.Nil(t, entries[0].ReservedUntil)
	require.NotNil(t, entries[0].ProfileID)
	require.Equal(t, int64(42), *entries[0].ProfileID)

	stale, err := st.Pool.Reserve("carrier-a", "", "stale", time.Hour)
	require.NoError(t, err)
	_, err = st.DB.Exec(`UPDATE iccid_pool SET reserved_until = ? WHERE iccid = ?`, time.Now().Add(-time.Hour).Unix(), stale)
	require.NoError(t, err)

	n, err := st.Pool.ReleaseExpired(time.Now().UTC())
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	got, _, err := st.Pool.ListPage("available", stale, ptr("carrier-a"), 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, len(got))
	require.Empty(t, got[0].Reference)

	// Stats are per tenant and expose the expired-reservation gauge.
	counts, ranges, err := st.Pool.Stats(ptr("carrier-a"))
	require.NoError(t, err)
	require.Equal(t, 1, ranges)
	require.GreaterOrEqual(t, counts["allocated"], 1)
	require.Contains(t, counts, "reservation_expired")

	all, ranges, err := st.Pool.Stats(nil)
	require.NoError(t, err)
	require.Equal(t, 2, ranges)
	require.GreaterOrEqual(t, all["available"], 1)
}

func TestProfileTenantFilterAndExternalRef(t *testing.T) {
	st := openTestStore(t)

	mk := func(tenant, iccid, ref string) *Profile {
		p := &Profile{ICCID: iccid, State: StateAllocated, TenantID: tenant, ExternalRef: ref}
		_, err := st.Profiles.Create(p)
		require.NoError(t, err)
		return p
	}
	mk("carrier-a", "8900012000000000001", "order-1")
	mk("carrier-b", "8900022000000000002", "order-1") // same ref, other tenant
	mk("", "8900032000000000003", "order-9")          // platform default

	items, total, err := st.Profiles.ListFiltered(ProfileFilter{Tenant: ptr("carrier-a")}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, "carrier-a", items[0].TenantID)

	items, total, err = st.Profiles.ListFiltered(ProfileFilter{Tenant: ptr("")}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Empty(t, items[0].TenantID)

	_, total, err = st.Profiles.ListFiltered(ProfileFilter{ExternalRef: "order-1"}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 2, total)

	// external_ref is unique per tenant.
	dup := &Profile{ICCID: "8900012000000000004", State: StateAllocated, TenantID: "carrier-a", ExternalRef: "order-1"}
	_, err = st.Profiles.Create(dup)
	require.Error(t, err)

	// A nil tenant spans every owner.
	_, total, err = st.Profiles.ListFiltered(ProfileFilter{}, 10, 0, "")
	require.NoError(t, err)
	require.Equal(t, 3, total)
}

func TestAuditAndEventTenantFilters(t *testing.T) {
	st := openTestStore(t)
	now := time.Now().UTC()

	insertAudit := func(tenant, fn string) {
		require.NoError(t, st.Audit.Insert(&AuditEntry{TS: now, TenantID: tenant, Interface: "es2p", Function: fn, Outcome: "Executed-Success"}))
	}
	insertAudit("carrier-a", "downloadOrder")
	insertAudit("carrier-b", "downloadOrder")
	insertAudit("", "downloadOrder")

	_, total, err := st.Audit.ListFiltered(AuditFilter{Tenant: ptr("carrier-a")}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)

	_, total, err = st.Audit.ListFiltered(AuditFilter{}, 10, 0)
	require.NoError(t, err)
	require.Equal(t, 3, total)

	buckets, err := st.Audit.Stats(AuditFilter{}, "tenant")
	require.NoError(t, err)
	require.Len(t, buckets, 3)

	if _, err := st.Audit.Stats(AuditFilter{}, "bogus"); err == nil {
		t.Fatal("expected an error for an unknown groupBy")
	}

	// Events: tenant filter plus lifecycle filters.
	for _, e := range []*EventRecord{
		{EID: "e1", EventID: "v1", CallerOID: "o1", RSPServerAddress: "dp", TenantID: "carrier-a", ICCID: "i1"},
		{EID: "e2", EventID: "v2", CallerOID: "o1", RSPServerAddress: "dp", TenantID: "carrier-b"},
	} {
		_, err := st.Events.Insert(e)
		require.NoError(t, err)
	}
	recs, total, err := st.Events.ListFiltered(EventFilter{Tenant: ptr("carrier-a")}, 10, 0, now)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Equal(t, "i1", recs[0].ICCID)

	recs, total, err = st.Events.ListFiltered(EventFilter{Tenant: ptr("carrier-a"), ICCID: "i1"}, 10, 0, now)
	require.NoError(t, err)
	require.Equal(t, 1, total)

	_, total, err = st.Events.ListFiltered(EventFilter{}, 10, 0, now)
	require.NoError(t, err)
	require.Equal(t, 2, total)

	// Soft-deleted rows leave the default (active) view.
	ok, err := st.Events.SoftDelete(recs[0].ID)
	require.NoError(t, err)
	require.True(t, ok)
	_, total, err = st.Events.ListFiltered(EventFilter{}, 10, 0, now)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	_, total, err = st.Events.ListFiltered(EventFilter{Status: "any"}, 10, 0, now)
	require.NoError(t, err)
	require.Equal(t, 2, total)
}

func ptr[T any](v T) *T { return &v }
