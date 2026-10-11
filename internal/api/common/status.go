// Package common holds shared JSON binding types and helpers for the ES2+,
// ES9+, ES11, ES12 and ES15 HTTP interfaces.
package common

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// AdminProtocolV2 is the value expected in the X-Admin-Protocol header.
const AdminProtocolV2 = "gsma/rsp/v2.2.0"

// ContentTypeJSON is the value used for all request and response bodies.
const ContentTypeJSON = "application/json"

// RequestHeader is the <JSON requestHeader> present on ES2+/ES12/ES15 requests.
type RequestHeader struct {
	FunctionRequesterIdentifier string `json:"functionRequesterIdentifier"`
	FunctionCallIdentifier      string `json:"functionCallIdentifier"`
}

// HeaderRequest is embedded by request types that carry a request header.
type HeaderRequest struct {
	Header RequestHeader `json:"header"`
}

// ExecutionStatus enumerates the top-level status values (SGP.22 §6.5.1).
type ExecutionStatus string

// Status values.
const (
	StatusExecutedSuccess     ExecutionStatus = "Executed-Success"
	StatusExecutedWithWarning ExecutionStatus = "Executed-WithWarning"
	StatusFailed              ExecutionStatus = "Failed"
	StatusExpired             ExecutionStatus = "Expired"
)

// StatusCodeData carries the subject/reason codes defined in SGP.22 §5.2.6.
type StatusCodeData struct {
	SubjectCode       string `json:"subjectCode"`
	ReasonCode        string `json:"reasonCode"`
	SubjectIdentifier string `json:"subjectIdentifier,omitempty"`
	Message           string `json:"message,omitempty"`
}

// FunctionExecutionStatus is the status object in every response header.
type FunctionExecutionStatus struct {
	Status         ExecutionStatus `json:"status"`
	StatusCodeData *StatusCodeData `json:"statusCodeData,omitempty"`
}

// ResponseHeader is the <JSON responseHeader> present on ES2+/ES12/ES15 responses.
type ResponseHeader struct {
	FunctionExecutionStatus FunctionExecutionStatus `json:"functionExecutionStatus"`
}

// HeaderResponse is embedded by response types that carry a response header.
type HeaderResponse struct {
	Header ResponseHeader `json:"header"`
}

// NewSuccess returns a successful response header.
func NewSuccess() HeaderResponse {
	return HeaderResponse{Header: ResponseHeader{FunctionExecutionStatus: FunctionExecutionStatus{Status: StatusExecutedSuccess}}}
}

// NewFailure returns a failed response header with the given status data.
func NewFailure(d *StatusCodeData) HeaderResponse {
	return HeaderResponse{Header: ResponseHeader{FunctionExecutionStatus: FunctionExecutionStatus{Status: StatusFailed, StatusCodeData: d}}}
}

// WriteJSON writes v as a JSON response with HTTP 200.
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}

// WriteNoContent writes an empty HTTP 204 response, as required for notification
// functions such as ES9+.HandleNotification and ES2+.HandleDownloadProgressInfo.
func WriteNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

// RequestIDFrom returns the request id stored in ctx, if any.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

type requestIDKey struct{}

// WithRequestID stores a request id in ctx.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}
