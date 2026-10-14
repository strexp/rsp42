package es2plus_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/api"
	"rsp42/internal/api/es2plus"
)

// TestHandleAcrRequestNotConfiguredIsJSON pins that the reserved inbound
// handleAcrRequest stub answers a JSON body instead of plain text, so a JSON
// client can parse the failure. rsp42 performs ACR outbound
// (service.ACRChecker); nothing wires ACRHandler yet.
func TestHandleAcrRequestNotConfiguredIsJSON(t *testing.T) {
	log := slog.New(slog.NewTextHandler(httptest.NewRecorder(), nil))
	h := es2plus.New(es2plus.Deps{Log: log})
	srv := httptest.NewServer(api.NewES2PRouter(log, h, api.Options{}))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/gsma/rsp2/es2plus/handleAcrRequest", "application/json", strings.NewReader("{}"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	require.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.Equal(t, "handleAcrRequest is not configured", body["error"])
}
