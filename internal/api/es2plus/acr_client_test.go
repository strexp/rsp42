package es2plus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api/common"
)

func TestHandleAcrRequestClient(t *testing.T) {
	var gotICCID string
	allow := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ICCID string `json:"iccid"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotICCID = req.ICCID
		if allow {
			common.WriteJSON(w, common.NewSuccess())
			return
		}
		common.WriteJSON(w, common.NewFailure(&common.StatusCodeData{SubjectCode: "8.2.1", ReasonCode: "1.2"}))
	}))
	defer srv.Close()

	c := NewCallbackClient("http://unused.example", "2.999.10", nil)
	c.ACRURL = srv.URL

	require.NoError(t, c.HandleAcrRequest(context.Background(), "89000123456789012341"))
	require.Equal(t, "89000123456789012341", gotICCID)

	allow = false
	require.Error(t, c.HandleAcrRequest(context.Background(), "89000123456789012341"))

	c.ACRURL = ""
	require.Error(t, c.HandleAcrRequest(context.Background(), "89000123456789012341"))
}
