// Package middleware provides the shared HTTP middleware stack for the ES2+,
// ES9+, ES11, ES12 and ES15 interfaces.
package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"

	"rsp42/internal/api/common"
	"rsp42/internal/audit"
)

// RequestID assigns a unique identifier to every request and echoes it back.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(common.WithRequestID(r.Context(), id)))
	})
}

// Logger logs each request with method, path, status and duration.
func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"bytes", sw.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", r.RemoteAddr,
				"request_id", common.RequestIDFrom(r.Context()),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// CORS enables browser cross-origin access for the listed origins. A `*` entry
// allows any origin. When the list is empty CORS is disabled. It answers
// preflight OPTIONS requests itself (chi has no OPTIONS routes).
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowAll := false
	allowed := map[string]bool{}
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
		}
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && (allowAll || allowed[origin]) {
				if allowAll {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				} else {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Add("Vary", "Origin")
				}
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Idempotency-Key, X-Request-ID, X-Admin-Protocol")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions && origin != "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Recover converts panics into JSON 500 responses and logs them with a stack
// trace. The body is deliberately generic: the panic detail is logged, not
// returned to the caller.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic", "value", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
					common.WriteHTTPError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// AdminProtocol validates the X-Admin-Protocol header, accepting any
// gsma/rsp/v2.x version. It always sets the response header.
func AdminProtocol(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Admin-Protocol", common.AdminProtocolV2)
		if p := r.Header.Get("X-Admin-Protocol"); p != "" && !strings.HasPrefix(p, "gsma/rsp/v2") {
			http.Error(w, "unsupported X-Admin-Protocol", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ContentType rejects POST bodies that are neither the JSON binding nor the
// ASN.1 binding (SGP.22 §6.5/§6.6) when a Content-Type is present.
func ContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ct := common.MediaType(r.Header.Get("Content-Type"))
			if ct != "" && ct != common.ContentTypeJSON && ct != common.ContentTypeASN1 {
				http.Error(w, "unsupported Content-Type", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Chain applies middleware in order.
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// RequestScope installs a mutable per-request audit scope. The actor is
// pre-filled from the mTLS peer certificate subject when present; handlers may
// refine it (ES2+ functionRequesterIdentifier, ES12 caller OID) and record the
// tenant attribution.
func RequestScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := &common.Scope{}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			s.Actor = r.TLS.PeerCertificates[0].Subject.String()
		}
		next.ServeHTTP(w, r.WithContext(common.WithScope(r.Context(), s)))
	})
}

// Audit records each request to the configured audit sinks. The actor and
// tenant come from the request scope (mTLS subject, ES2+ requester identifier,
// or the ES12 caller OID); X-Request-ID is kept as a correlation detail, and any
// detail the handler contributed to the scope is merged in.
func Audit(l *audit.Logger, iface string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			outcome := "Executed-Success"
			if sw.status >= 400 {
				outcome = "Failed"
			}
			function := auditFunction(r.URL.Path)
			var actor, tenant string
			detail := map[string]any{}
			if s := common.ScopeFrom(r.Context()); s != nil {
				actor, tenant = s.Actor, s.TenantID
				if s.Function != "" {
					function = s.Function
				}
				for k, v := range s.Detail {
					detail[k] = v
				}
			}
			if id := r.Header.Get("X-Request-ID"); id != "" {
				detail["requestId"] = id
			}
			if len(detail) == 0 {
				detail = nil
			}
			l.Log(audit.Entry{
				Actor:      actor,
				TenantID:   tenant,
				Interface:  iface,
				Function:   function,
				Outcome:    outcome,
				StatusCode: fmt.Sprintf("%d", sw.status),
				RemoteAddr: r.RemoteAddr,
				Detail:     detail,
			})
		})
	}
}

// auditFunction reduces a protocol path to the function name the caller invoked,
// so `GET /audit?function=downloadOrder` matches and groupBy=function groups by
// function rather than by path. The RSP interfaces name the function in the last
// segment (/gsma/rsp2/es2plus/downloadOrder); the ASN.1 binding uses one generic
// path for every function, so its handler sets the name on the request scope
// instead. Anything else (the management API) keeps its path.
func auditFunction(path string) string {
	const prefix = "/gsma/rsp2/"
	if !strings.HasPrefix(path, prefix) {
		return path
	}
	rest := path[len(prefix):]
	i := strings.IndexByte(rest, '/')
	if i < 0 || i == len(rest)-1 {
		return path // e.g. /gsma/rsp2/asn1: the path does not name a function
	}
	iface, fn := rest[:i], rest[i+1:]
	switch iface {
	case "es2plus", "es9plus", "es11", "es12", "es15":
		return fn
	}
	return path
}

// MaxBody limits the size of request bodies and publishes the budget in the
// request context, so that downstream readers (the idempotency replay buffer,
// common.ReadJSON/ReadRaw) share one authoritative limit instead of each
// carrying its own constant.
func MaxBody(n int64) func(http.Handler) http.Handler {
	if n <= 0 {
		n = common.DefaultBodyLimit
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r.WithContext(common.WithBodyLimit(r.Context(), n)))
		})
	}
}
