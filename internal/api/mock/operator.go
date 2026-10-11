// Package mock contains a test-only mock Operator implementing the ES2+ server
// side (handleDownloadProgressInfo, handleAcrRequest) used for end-to-end self
// tests. It is not a production component.
package mock

import (
	"encoding/json"
	"net/http"
	"sync"

	"rsp42/internal/api/common"
)

// Operator is a mock ES2+ operator endpoint.
type Operator struct {
	mu          sync.Mutex
	Progress    []json.RawMessage
	ACRRequests []json.RawMessage
}

// NewOperator returns a mock operator.
func NewOperator() *Operator { return &Operator{} }

// Handler returns the mock operator's HTTP handler.
func (o *Operator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/gsma/rsp2/es2plus/handleDownloadProgressInfo", o.handleProgress)
	mux.HandleFunc("/gsma/rsp2/es2plus/handleAcrRequest", o.handleACR)
	return mux
}

func (o *Operator) handleProgress(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := readJSON(r, &raw); err == nil {
		o.mu.Lock()
		o.Progress = append(o.Progress, raw)
		o.mu.Unlock()
	}
	// Notification functions return HTTP 204.
	w.WriteHeader(http.StatusNoContent)
}

func (o *Operator) handleACR(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := readJSON(r, &raw); err == nil {
		o.mu.Lock()
		o.ACRRequests = append(o.ACRRequests, raw)
		o.mu.Unlock()
	}
	common.WriteJSON(w, map[string]any{"header": common.NewSuccess().Header})
}

// ProgressCount returns the number of received progress notifications.
func (o *Operator) ProgressCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.Progress)
}

func readJSON(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(v)
}
