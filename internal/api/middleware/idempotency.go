package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"rsp42/internal/api/common"
	"rsp42/internal/store"
)

// IdempotencyStore is the persistence the replay middleware needs. It is
// defined by the consumer so the SQLite repository stays a detail;
// *store.IdempotencyRepo satisfies it.
type IdempotencyStore interface {
	Claim(key, endpoint, tenant, requestHash string) (rec *store.IdempotencyRecord, replay bool, err error)
	Complete(key, endpoint, tenant string, status int, responseJSON string) error
	Abort(key, endpoint string) error
}

// maxReplayBody is the fallback budget for the replay buffer when no
// middleware.MaxBody ran ahead of it (i.e. the router's budget is unknown).
const maxReplayBody = common.DefaultBodyLimit

type replayResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"contentType,omitempty"`
	Body        string `json:"body,omitempty"` // base64
}

// Idempotency implements keyed write replay using the `Idempotency-Key` HTTP
// header. SGP.22 §6.2 explicitly allows additional HTTP header fields, so this
// needs no request-body extension (G5). Only applied to routes whose functions
// have no standard resend semantic (ConfirmOrder/ReleaseProfile/CancelOrder and
// the equivalent Admin API writes).
//
// Semantics: same key + same path + same body replays the recorded response and
// repeats no side effect; same key with a different body is a 409; a 5xx
// response releases the key so the caller may retry.
func Idempotency(repo IdempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if nilStore(repo) {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}
			// Buffer within the router's budget so the idempotency hash sees
			// the same body the handler will (a larger admin upload must not be
			// truncated by a smaller constant here).
			limit := maxReplayBody
			if n, ok := common.BodyLimitFrom(r.Context()); ok && n > limit {
				limit = n
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil {
				writeReplayErr(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the idempotency buffer")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			endpoint := r.URL.Path
			hash := requestHash(r.Method, endpoint, body)

			rec, replay, err := repo.Claim(key, endpoint, scopeTenant(r), hash)
			switch {
			case errors.Is(err, store.ErrIdempotencyConflict):
				writeReplayErr(w, http.StatusConflict, "idempotency_key_reused", "Idempotency-Key was already used with a different request")
				return
			case errors.Is(err, store.ErrIdempotencyInFlight):
				writeReplayErr(w, http.StatusConflict, "idempotency_key_in_flight", "an identical request is still being processed")
				return
			case err != nil:
				http.Error(w, "idempotency store unavailable", http.StatusInternalServerError)
				return
			case replay:
				var rr replayResponse
				if jerr := json.Unmarshal([]byte(rec.ResponseJSON), &rr); jerr != nil {
					http.Error(w, "idempotency record corrupt", http.StatusInternalServerError)
					return
				}
				if rr.ContentType != "" {
					w.Header().Set("Content-Type", rr.ContentType)
				}
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(rr.Status)
				_, _ = w.Write(decodeReplayBody(rr.Body))
				return
			}

			rw := &replayWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, r)
			if rw.status >= 500 {
				_ = repo.Abort(key, endpoint)
				return
			}
			blob, _ := json.Marshal(replayResponse{
				Status:      rw.status,
				ContentType: w.Header().Get("Content-Type"),
				Body:        base64.StdEncoding.EncodeToString(rw.buf.Bytes()),
			})
			_ = repo.Complete(key, endpoint, scopeTenant(r), rw.status, string(blob))
		})
	}
}

// requestHash hashes a request for replay detection. The ES2+/ES12
// header.functionCallIdentifier is a per-call trace identifier that every retry
// regenerates, so it is excluded: without that, a legitimate resend would look
// like a different request.
func requestHash(method, endpoint string, body []byte) string {
	canonical := body
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err == nil {
		if hdr, ok := doc["header"].(map[string]any); ok {
			delete(hdr, "functionCallIdentifier")
			if b, merr := json.Marshal(doc); merr == nil {
				canonical = b
			}
		}
	}
	sum := sha256.Sum256(append([]byte(method+" "+endpoint+"\x00"), canonical...))
	return hex.EncodeToString(sum[:])
}

func scopeTenant(r *http.Request) string {
	if s := common.ScopeFrom(r.Context()); s != nil {
		return s.TenantID
	}
	return ""
}

func decodeReplayBody(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func writeReplayErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": msg})
}

type replayWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (w *replayWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *replayWriter) Write(b []byte) (int, error) {
	if n := int64(w.buf.Len()); n < maxReplayBody {
		remaining := maxReplayBody - n
		if int64(len(b)) > remaining {
			w.buf.Write(b[:remaining])
		} else {
			w.buf.Write(b)
		}
	}
	return w.ResponseWriter.Write(b)
}

// nilStore reports whether a store dependency is absent. A typed nil pointer
// stored in an interface is not == nil, so the plain comparison would let a
// disabled store through and panic on first use.
func nilStore(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}
