package admin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAdminCallbacksQueue pins N2's management API: the outbound callback queue
// is listable (payload as a parsed object), a single dead letter can be
// re-driven, and a batch re-drive works.
func TestAdminCallbacksQueue(t *testing.T) {
	srv, st := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	idA, err := st.Callbacks.Enqueue("https://bss.example/es2p",
		`{"tenantId":"carrier-a","iccid":"89000123456789012341","notificationPointId":3,"timestamp":"2026-01-01T00:00:00Z"}`, 3)
	require.NoError(t, err)
	idB, err := st.Callbacks.Enqueue("https://bss.example/es2p",
		`{"tenantId":"carrier-b","iccid":"89000123456789012342","notificationPointId":4}`, 4)
	require.NoError(t, err)

	// List with a tenant filter; the payload comes back as an object.
	status, raw := do(t, "GET", base+"/callbacks?tenant=carrier-a", nil)
	require.Equal(t, 200, status, string(raw))
	var list struct {
		Items []struct {
			ID      int64          `json:"id"`
			State   string         `json:"state"`
			Payload map[string]any `json:"payload"`
		} `json:"items"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Equal(t, 1, list.Total)
	require.Equal(t, idA, list.Items[0].ID)
	require.Equal(t, "carrier-a", list.Items[0].Payload["tenantId"])
	require.EqualValues(t, 3, list.Items[0].Payload["notificationPointId"])

	// Re-queueing a live callback is refused.
	status, raw = do(t, "POST", base+"/callbacks/"+itoa(idA)+"/retry", nil)
	require.Equal(t, 409, status, string(raw))

	// An unknown id is a 404.
	status, _ = do(t, "POST", base+"/callbacks/99999/retry", nil)
	require.Equal(t, 404, status)

	// Dead-letter both, then re-drive one by id.
	require.NoError(t, st.Callbacks.MarkFailed(idA, "boom"))
	require.NoError(t, st.Callbacks.MarkFailed(idB, "boom"))
	status, raw = do(t, "GET", base+"/callbacks?state=dead", nil)
	require.Equal(t, 200, status, string(raw))
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Equal(t, 2, list.Total)

	status, raw = do(t, "POST", base+"/callbacks/"+itoa(idA)+"/retry", nil)
	require.Equal(t, 200, status, string(raw))
	var one struct {
		ID       int64  `json:"id"`
		State    string `json:"state"`
		Attempts int    `json:"attempts"`
	}
	require.NoError(t, json.Unmarshal(raw, &one))
	require.Equal(t, idA, one.ID)
	require.Equal(t, "pending", one.State)
	require.Zero(t, one.Attempts)

	// Batch re-drive the remaining dead letter.
	status, raw = do(t, "POST", base+"/callbacks/retry-dead", map[string]any{"limit": 10})
	require.Equal(t, 200, status, string(raw))
	var batch struct {
		Requeued int `json:"requeued"`
	}
	require.NoError(t, json.Unmarshal(raw, &batch))
	require.Equal(t, 1, batch.Requeued)
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
