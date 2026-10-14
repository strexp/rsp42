package admin

import (
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

// fakeTenantStore is an in-memory TenantStore. It proves the handler depends on
// the seam and not on SQLite: no database is opened in this file.
type fakeTenantStore struct {
	tenants []*store.Tenant
	deleted []string
}

func (f *fakeTenantStore) Delete(id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeTenantStore) DeleteWithReassign(id, reassignTo string) error {
	f.deleted = append(f.deleted, id+"->"+reassignTo)
	return nil
}

func (f *fakeTenantStore) Get(id string) (*store.Tenant, error) {
	for _, t := range f.tenants {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeTenantStore) List() ([]*store.Tenant, error) { return f.tenants, nil }

func (f *fakeTenantStore) Upsert(t *store.Tenant) error {
	f.tenants = append(f.tenants, t)
	return nil
}

func (f *fakeTenantStore) Usage(string) (store.TenantUsage, error) { return store.TenantUsage{}, nil }

// TestHandlerRunsOnInjectedStores is the dependency-inversion regression: the
// management API must serve a resource through the interface it declares, with
// no SQLite and no other resource wired.
func TestHandlerRunsOnInjectedStores(t *testing.T) {
	quota := 5
	fake := &fakeTenantStore{tenants: []*store.Tenant{{
		ID: "carrier-a", Name: "Carrier A", Status: store.TenantActive,
		ProfileQuota: &quota, CreatedAt: time.Unix(1, 0).UTC(),
	}}}

	h := &Handler{
		Log:     slog.New(slog.NewTextHandler(httptest.NewRecorder(), nil)),
		Tenants: fake,
	}
	r := chi.NewRouter()
	Mount(r, h)
	srv := httptest.NewServer(r)
	defer srv.Close()

	status, raw := testutil.DoJSON(t, "GET", srv.URL+"/admin/api/v1/tenants", nil)
	require.Equal(t, 200, status, string(raw))

	var body struct {
		Items []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			ProfileQuota *int   `json:"profileQuota"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Equal(t, 1, body.Total)
	require.Len(t, body.Items, 1)
	require.Equal(t, "carrier-a", body.Items[0].ID)
	require.Equal(t, "Carrier A", body.Items[0].Name)
	require.NotNil(t, body.Items[0].ProfileQuota)
	require.Equal(t, 5, *body.Items[0].ProfileQuota)

	// A partially wired handler is a wiring bug, not a request-time condition:
	// Validate names every missing seam so the composition root can refuse to
	// serve (previously some handlers answered 501 and others panicked).
	err := h.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "Profiles")
	require.Contains(t, err.Error(), "UPP")
	require.Contains(t, err.Error(), "Pool")

	// Audit, Idem and AllowedSAIP are optional and must not be reported.
	require.NotContains(t, err.Error(), "Audit")
	require.NotContains(t, err.Error(), "Idem")
	require.NotContains(t, err.Error(), "AllowedSAIP")
}
