package common

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"rsp42/internal/rsp"
)

// B64 encodes binary data for the JSON binding.
func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// DecodeB64 decodes a base64 string from the JSON binding.
func DecodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// WriteSuccess writes a successful JSON body with an optional set of extra
// top-level fields alongside the response header.
func WriteSuccess(w http.ResponseWriter, extra map[string]any) {
	resp := map[string]any{"header": NewSuccess().Header}
	for k, v := range extra {
		resp[k] = v
	}
	WriteJSON(w, resp)
}

// WriteFailure writes an HTTP 200 response with a Failed execution status.
func WriteFailure(w http.ResponseWriter, subject, reason, message string) {
	WriteJSON(w, map[string]any{"header": NewFailure(&StatusCodeData{
		SubjectCode: subject, ReasonCode: reason, Message: message,
	}).Header})
}

// WriteCode writes a Failed execution status using a named SGP.22 status code.
func WriteCode(w http.ResponseWriter, code rsp.Code, message string) {
	WriteFailure(w, code.Subject, code.Reason, message)
}

// WriteStatusFailure maps an error to a Failed execution status. A *rsp.StatusCode
// keeps its own subject/reason code; anything else becomes a generic failure.
func WriteStatusFailure(w http.ResponseWriter, err error) {
	var sc *rsp.StatusCode
	if errors.As(err, &sc) {
		WriteFailure(w, sc.SubjectCode, sc.ReasonCode, sc.Message)
		return
	}
	WriteCode(w, rsp.CodeVerificationFailed, err.Error())
}

// ReadRaw reads a request body with a size limit.
func ReadRaw(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
}

// ReadJSON reads and decodes a JSON request body with a size limit. It does not
// write a response on failure; the caller decides the interface-specific code.
func ReadJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return io.EOF
	}
	return json.Unmarshal(body, v)
}

// WriteHTTPError writes an HTTP-level failure as a JSON object.
//
// SGP.22 §6.2 defines an RSP response only for HTTP 200, so a 4xx/5xx answer is
// not a functionExecutionStatus envelope: it is reported as {"error": ...} so a
// JSON client can still parse it. Protocol failures that the RSP layer can
// classify must use WriteCode/WriteFailure instead.
func WriteHTTPError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
