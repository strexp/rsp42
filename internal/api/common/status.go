// Package common holds shared JSON binding types and helpers for the ES2+,
// ES9+, ES11, ES12 and ES15 HTTP interfaces.
package common

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// AdminProtocolV2 is the X-Admin-Protocol value rsp42 advertises and accepts
// (SGP.22 §6.5/§6.6: "gsma/rsp/v<x.y.z>"). The implemented revision is v2.7, so
// the response advertises that; the middleware still accepts any gsma/rsp/v2.x
// request header.
const AdminProtocolV2 = "gsma/rsp/v2.7.0"

// ContentTypeJSON is the value used for the JSON binding (SGP.22 §6.5).
const ContentTypeJSON = "application/json"

// ContentTypeASN1 is the value used for the ASN.1 binding (SGP.22 §6.6).
const ContentTypeASN1 = "application/x-gsma-rsp-asn1"

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

// WriteASN1 writes a DER-encoded ASN.1 binding response (SGP.22 §6.6).
func WriteASN1(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", ContentTypeASN1)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// MediaType returns the media type of a Content-Type header value, dropping any
// parameters (e.g. "; charset=utf-8").
func MediaType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
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
