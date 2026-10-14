package admin

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/store"
	"rsp42/internal/testutil"
)

type auditCursorPage struct {
	Items []struct {
		ID int64 `json:"id"`
	} `json:"items"`
	NextAfterID int64 `json:"nextAfterId"`
	HasMore     bool  `json:"hasMore"`
}

// TestAdminAuditIncrementalCursor pins N1's endpoint: afterId is an exclusive
// cursor with an ascending order, and the nextAfterId resumption produces no
// duplicate and no gap.
func TestAdminAuditIncrementalCursor(t *testing.T) {
	srv, st := newTestServer(t)
	base := srv.URL + "/admin/api/v1"

	for i := 0; i < 3; i++ {
		require.NoError(t, st.Audit.Insert(&store.AuditEntry{
			Interface: "es9p", Function: "authenticateClient", Outcome: "Executed-Success",
		}))
	}

	status, raw := testutil.DoJSON(t, "GET", base+"/audit?afterId=0&limit=2", nil)
	require.Equal(t, 200, status, string(raw))
	var first auditCursorPage
	require.NoError(t, json.Unmarshal(raw, &first))
	require.Len(t, first.Items, 2)
	require.True(t, first.HasMore)
	require.Equal(t, first.Items[1].ID, first.NextAfterID)

	status, raw = testutil.DoJSON(t, "GET", fmt.Sprintf("%s/audit?afterId=%d&limit=2", base, first.NextAfterID), nil)
	require.Equal(t, 200, status, string(raw))
	var second auditCursorPage
	require.NoError(t, json.Unmarshal(raw, &second))
	require.Len(t, second.Items, 1)
	require.False(t, second.HasMore)
	require.Greater(t, second.Items[0].ID, first.Items[1].ID, "cursor resumes strictly after the previous batch")

	// An empty batch echoes afterId unchanged.
	status, raw = testutil.DoJSON(t, "GET", fmt.Sprintf("%s/audit?afterId=%d&limit=2", base, second.NextAfterID), nil)
	require.Equal(t, 200, status, string(raw))
	var empty auditCursorPage
	require.NoError(t, json.Unmarshal(raw, &empty))
	require.Empty(t, empty.Items)
	require.Equal(t, second.NextAfterID, empty.NextAfterID)

	// afterId is mutually exclusive with page/size.
	status, raw = testutil.DoJSON(t, "GET", base+"/audit?afterId=0&page=1", nil)
	require.Equal(t, 400, status, string(raw))
	require.Contains(t, string(raw), "invalid_request")

	// afterId must be a non-negative integer.
	status, _ = testutil.DoJSON(t, "GET", base+"/audit?afterId=-1", nil)
	require.Equal(t, 400, status)
}
