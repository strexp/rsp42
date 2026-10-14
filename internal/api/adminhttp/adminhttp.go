// Package adminhttp holds the HTTP conventions shared by the management APIs
// (the SM-DP+ admin package and the SM-DS dsadmin package): the JSON response
// and error model, the body decoding, and the `?page=`/`?size=` list envelope.
//
// It exists so the two management surfaces cannot drift apart, and so neither
// has to import the other. It deliberately knows nothing about the resources
// being managed.
package adminhttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Actor is the fixed audit actor recorded for the management API: it is
// unauthenticated by design (the security boundary is the calling backend, see
// docs/esim42-integration-gaps.md §8.1 decision 5), so every entry carries the
// same internal identity.
const Actor = "esim42-backend"

// List paging defaults and bounds, mirrored by openapi.json.
const (
	DefaultPageSize = 50
	MaxPageSize     = 500
)

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteErr writes the stable management-API error body for a status: the message
// is the human-readable text and the code is derived from the status (G10).
func WriteErr(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, ErrorBody(ErrCode(status), msg))
}

// ErrorBody is the stable management-API error model (G10).
func ErrorBody(code, message string) map[string]string {
	return map[string]string{"code": code, "message": message}
}

// ErrorBodyDetails is ErrorBody plus a machine-readable details object. It is
// used where a stable code alone is not enough to act on (N16, N3).
func ErrorBodyDetails(code, message string, details any) map[string]any {
	body := map[string]any{"code": code, "message": message}
	if details != nil {
		body["details"] = details
	}
	return body
}

// ErrCode derives a stable machine-readable code from the HTTP status when a
// handler has no more specific one. Every status a handler can produce maps to a
// named code; there is deliberately no bare "error" code (N7).
func ErrCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnprocessableEntity:
		return "unprocessable_entity"
	case http.StatusNotImplemented:
		return "not_implemented"
	default:
		if status >= 500 {
			return "internal_error"
		}
		return "request_failed"
	}
}

// ReadJSON decodes a management-API request body, reporting the failure with a
// 400 and the shared error body. The size budget comes from
// middleware.MaxBody (api.Options.BodyLimit), so no separate limit applies.
func ReadJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		WriteErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// AtoiDefault parses a query integer, returning def when it is absent or
// malformed.
func AtoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// TenantFilter returns the `?tenant=` filter: nil when absent, a pointer to the
// raw value otherwise ("" selects the platform-default rows).
func TenantFilter(r *http.Request) *string {
	q := r.URL.Query()
	if !q.Has("tenant") {
		return nil
	}
	t := strings.TrimSpace(q.Get("tenant"))
	return &t
}

// ClampSize bounds a page size to [1, MaxPageSize], falling back to
// DefaultPageSize.
func ClampSize(n int) int {
	if n < 1 {
		return DefaultPageSize
	}
	if n > MaxPageSize {
		return MaxPageSize
	}
	return n
}

// ClampPage bounds a 1-based page number.
func ClampPage(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// ParsePage reads the shared `?page=`/`?size=` parameters with the
// management-API defaults and bounds.
func ParsePage(r *http.Request) (page, size int) {
	q := r.URL.Query()
	page = ClampPage(AtoiDefault(q.Get("page"), 1))
	size = ClampSize(AtoiDefault(q.Get("size"), DefaultPageSize))
	return page, size
}

// WriteListEnvelope writes the shared paginated list body
// `{"items": ..., "page": ..., "size": ..., "total": ...}`.
func WriteListEnvelope[T any](w http.ResponseWriter, items T, page, size, total int) {
	WriteJSON(w, http.StatusOK, map[string]any{
		"items": items, "page": page, "size": size, "total": total,
	})
}

// ParseID parses a positive identifier.
func ParseID(s string) (int64, error) {
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid id %q", s)
	}
	return id, nil
}

// ParseTime parses a query timestamp; nil when empty or unparsable.
func ParseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// FirstNonEmpty returns the first non-empty string.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
