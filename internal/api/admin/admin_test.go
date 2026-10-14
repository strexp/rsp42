package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"rsp42/internal/kms"
	"rsp42/internal/service"
	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

func newTestServer(t *testing.T, opts ...func(*Handler)) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open("file:" + filepath.Join(t.TempDir(), "admin.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	provider, err := kms.NewFileProviderFromKEK([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	inv := service.NewInventory(st.Profiles, "8900012", "00101")
	inv.Pool = st.Pool
	inv.ReserveTTL = time.Hour
	inv.ProfileQuota = func(tenant string) (*int, error) {
		tn, err := st.Tenants.Get(tenant)
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return tn.ProfileQuota, nil
	}
	inv.CountProfiles = func(tenant string) (int, error) {
		_, total, err := st.Profiles.ListFiltered(store.ProfileFilter{Tenant: &tenant}, 1, 0, "")
		return total, err
	}
	orders := service.NewOrderService(st.Profiles)
	orders.Pool = st.Pool
	h := &Handler{
		Log: slog.Default(), Tenants: st.Tenants, Profiles: st.Profiles,
		Orders: orders, Inventory: inv,
		UPP: st.UPP, Perso: service.NewPersonalizationService(st.Perso, provider), Audit: st.Audit, Batch: st.Batch,
		OrderRepo: st.Orders, Notifs: st.Notifs, Sessions: st.Sessions, Pool: st.Pool,
		Callbacks: st.Callbacks,
		Idem:      st.Idem, DefaultReserveTTL: time.Hour,
		FQDN: "testsmdpplus1.example.com", OID: "2.999.10",
	}
	for _, o := range opts {
		o(h)
	}
	r := chi.NewRouter()
	Mount(r, h)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, st
}

func TestAdminProfilesCRUD(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	// Create (downloadOrder).
	var created map[string]any
	status, raw := testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational"})
	require.Equal(t, 201, status)
	require.NoError(t, json.Unmarshal(raw, &created))
	iccid, _ := created["iccid"].(string)
	require.NotEmpty(t, iccid)

	// List + filter.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles?state=Allocated&size=10", nil)
	require.Equal(t, 200, status)
	var list struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Equal(t, 1, list.Total)

	// Get.
	status, _ = testutil.DoJSON(t, "GET", base+"/profiles/"+iccid, nil)
	require.Equal(t, 200, status)

	// Patch (set matchingId).
	status, _ = testutil.DoJSON(t, "PATCH", base+"/profiles/"+iccid, map[string]any{"matchingId": "ADMIN-1"})
	require.Equal(t, 200, status)

	// Confirm (release) then activation code.
	status, _ = testutil.DoJSON(t, "POST", base+"/profiles/"+iccid+"/confirm", map[string]any{"release": true})
	require.Equal(t, 200, status)
	status, raw = testutil.DoJSON(t, "POST", base+"/profiles/"+iccid+"/activation-code", nil)
	require.Equal(t, 200, status)
	var ac map[string]any
	require.NoError(t, json.Unmarshal(raw, &ac))
	require.Contains(t, ac["activationCode"], "ADMIN-1")

	// Timeline contains the order events.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles/"+iccid+"/timeline", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"kind":"order"`)

	// Delete.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/profiles/"+iccid, nil)
	require.Equal(t, 204, status)
	status, _ = testutil.DoJSON(t, "GET", base+"/profiles/"+iccid, nil)
	require.Equal(t, 404, status)
}

func TestAdminUPPAndPersonalization(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	// Upload a UPP (base64) and check the parsed SAIP version.
	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	status, raw := testutil.DoJSON(t, "POST", base+"/upp", map[string]any{
		"name": "TS48v1_A.der", "data": base64.StdEncoding.EncodeToString(der),
	})
	require.Equal(t, 200, status)
	var view map[string]any
	require.NoError(t, json.Unmarshal(raw, &view))
	require.Equal(t, "2.1", view["saip"])

	// List / bytes / deactivate / delete.
	status, raw = testutil.DoJSON(t, "GET", base+"/upp", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "TS48v1_A.der")
	status, _ = testutil.DoJSON(t, "GET", base+"/upp/TS48v1_A.der/bytes", nil)
	require.Equal(t, 200, status)
	status, _ = testutil.DoJSON(t, "POST", base+"/upp/TS48v1_A.der/deactivate", nil)
	require.Equal(t, 200, status)
	status, _ = testutil.DoJSON(t, "DELETE", base+"/upp/TS48v1_A.der", nil)
	require.Equal(t, 204, status)

	// Personalization: put then reveal.
	k := "465B5CE8B199B49FAA5F0A2EE238A6BC"
	status, _ = testutil.DoJSON(t, "PUT", base+"/personalization/89000123456789012341", map[string]any{
		"imsi": "001010123456063", "k": k, "algorithm": "milenage",
	})
	require.Equal(t, 200, status)
	status, raw = testutil.DoJSON(t, "GET", base+"/personalization/89000123456789012341?reveal=1", nil)
	require.Equal(t, 200, status)
	var pv map[string]any
	require.NoError(t, json.Unmarshal(raw, &pv))
	require.Equal(t, k, pv["k"])
	require.Equal(t, true, pv["hasK"])

	// Bulk import.
	status, raw = testutil.DoJSON(t, "POST", base+"/personalization/import", map[string]any{
		"records": []map[string]any{{"iccid": "89000123456789012342", "imsi": "001010123456064", "spn": "BULK"}},
	})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"imported":1`)

	// List + delete.
	status, raw = testutil.DoJSON(t, "GET", base+"/personalization?size=10", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"total":2`)
	status, _ = testutil.DoJSON(t, "DELETE", base+"/personalization/89000123456789012342", nil)
	require.Equal(t, 204, status)
}

func TestAdminBatchesAndBulk(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	status, raw := testutil.DoJSON(t, "POST", base+"/batches", map[string]any{"name": "B1", "count": 3, "profileType": "operational"})
	require.Equal(t, 201, status)
	var created struct {
		ID int64 `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))
	require.NotZero(t, created.ID)
	idStr := strconv.FormatInt(created.ID, 10)

	// Items.
	status, raw = testutil.DoJSON(t, "GET", base+"/batches/"+idStr+"/items?size=10", nil)
	require.Equal(t, 200, status)
	var items struct {
		Items []struct {
			ICCID string `json:"iccid"`
			State string `json:"state"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &items))
	require.Equal(t, 3, items.Total)

	// State breakdown.
	status, raw = testutil.DoJSON(t, "GET", base+"/batches/"+idStr, nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "Allocated")

	// Confirm the whole batch (release=true).
	status, raw = testutil.DoJSON(t, "POST", base+"/batches/"+idStr+"/confirm", map[string]any{"release": true})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"applied":3`)

	// Bulk cancel back to Available.
	iccids := make([]string, 0, len(items.Items))
	for _, it := range items.Items {
		iccids = append(iccids, it.ICCID)
	}
	status, raw = testutil.DoJSON(t, "POST", base+"/profiles/bulk", map[string]any{"action": "cancel", "iccids": iccids, "finalStatus": "Available"})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"ok":true`)

	// Delete the batch.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/batches/"+idStr, nil)
	require.Equal(t, 204, status)
}

func TestAdminICCIDPoolAndDecoded(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	// Import a range.
	status, raw := testutil.DoJSON(t, "POST", base+"/iccid-ranges", map[string]any{
		"start": "8900012000000000000", "end": "8900012000000000199", "note": "test",
	})
	require.Equal(t, 201, status)
	var imp struct {
		RangeID  int64 `json:"rangeId"`
		Inserted int   `json:"inserted"`
	}
	require.NoError(t, json.Unmarshal(raw, &imp))
	require.Greater(t, imp.Inserted, 0)

	// Stats + reserve.
	status, raw = testutil.DoJSON(t, "GET", base+"/iccid-pool/stats", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "available")

	status, raw = testutil.DoJSON(t, "POST", base+"/iccid-pool/reserve", map[string]any{"eid": "EID-X"})
	require.Equal(t, 200, status)
	var reserved struct {
		ICCID string `json:"iccid"`
	}
	require.NoError(t, json.Unmarshal(raw, &reserved))
	require.NotEmpty(t, reserved.ICCID)

	// Allocation now prefers the pool: a new profile consumes one pool ICCID.
	status, raw = testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational"})
	require.Equal(t, 201, status)
	var created struct {
		ICCID string `json:"iccid"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))
	require.True(t, strings.HasPrefix(created.ICCID, "89000120"), "expected a pool ICCID, got %s", created.ICCID)

	// Release the reserved one.
	status, _ = testutil.DoJSON(t, "POST", base+"/iccid-pool/release", map[string]any{"iccid": reserved.ICCID})
	require.Equal(t, 200, status)

	// Delete the range.
	status, _ = testutil.DoJSON(t, "DELETE", base+"/iccid-ranges/"+strconv.FormatInt(imp.RangeID, 10), nil)
	require.Equal(t, 200, status)

	// UPP decoded view.
	der, err := os.ReadFile("../../../testdata/upp/TS48v1_A.der")
	require.NoError(t, err)
	testutil.DoJSON(t, "POST", base+"/upp", map[string]any{"name": "u.der", "data": base64.StdEncoding.EncodeToString(der)})
	status, raw = testutil.DoJSON(t, "GET", base+"/upp/u.der/decoded", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"name":"header"`)
	require.Contains(t, string(raw), `"services"`)
}

func TestAdminExportImport(t *testing.T) {
	srv, _ := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational", "matchingId": "M-EXP"})

	// Export CSV.
	status, raw := testutil.DoJSON(t, "GET", base+"/profiles/export?format=csv", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "iccid,tenant,externalRef,imsi,profileType")

	// Export JSON + re-import one record.
	status, raw = testutil.DoJSON(t, "GET", base+"/profiles/export?format=json", nil)
	require.Equal(t, 200, status)
	var exp struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(raw, &exp))
	require.NotEmpty(t, exp.Items)

	status, raw = testutil.DoJSON(t, "POST", base+"/profiles/import", map[string]any{
		"records": []map[string]any{{"iccid": "89000123456789012341", "profileType": "operational"}},
	})
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), `"imported":1`)

	// Personalization export.
	testutil.DoJSON(t, "PUT", base+"/personalization/89000123456789012341", map[string]any{"imsi": "001010123456063", "k": "465B5CE8B199B49FAA5F0A2EE238A6BC"})
	status, raw = testutil.DoJSON(t, "GET", base+"/personalization/export?format=csv", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "iccid,imsi,k,opc")
}

func TestAdminOpenAPIAndAudit(t *testing.T) {
	srv, st := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	status, raw := testutil.DoJSON(t, "GET", base+"/openapi.json", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "/admin/api/v1/profiles")

	// Mutations are audited.
	testutil.DoJSON(t, "POST", base+"/profiles", map[string]any{"profileType": "operational"})
	entries, err := st.Audit.List(10)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	require.Equal(t, "admin", entries[0].Interface)
	require.Equal(t, "createProfile", entries[0].Function)

	// ... and queryable through the management API.
	status, raw = testutil.DoJSON(t, "GET", base+"/audit?interface=admin&size=10", nil)
	require.Equal(t, 200, status)
	require.Contains(t, string(raw), "createProfile")
	require.Contains(t, string(raw), `"total":`)
}
