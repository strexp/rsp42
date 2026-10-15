package mockoperator

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
	// RefuseACR makes handleAcrRequest answer Failed with the spec's specific
	// code (8.2.1/1.2, "Profile ICCID Not Allowed"), exercising the refusal path.
	RefuseACR bool
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
	o.mu.Lock()
	refuse := o.RefuseACR
	o.mu.Unlock()
	if refuse {
		common.WriteJSON(w, common.NewFailure(&common.StatusCodeData{
			SubjectCode: "8.2.1", ReasonCode: "1.2", Message: "Profile ICCID Not Allowed",
		}))
		return
	}
	common.WriteJSON(w, map[string]any{"header": common.NewSuccess().Header})
}

// ACRCount returns the number of received HandleAcrRequest calls.
func (o *Operator) ACRCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.ACRRequests)
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
