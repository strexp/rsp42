// Package middleware provides the shared HTTP middleware stack for the ES2+,
// ES9+, ES11, ES12 and ES15 interfaces.
package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
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

// Recover converts panics into 500 responses and logs them.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic", "value", rec, "path", r.URL.Path)
					http.Error(w, "internal server error", http.StatusInternalServerError)
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

// ContentType rejects POST bodies that are not JSON when a body is present.
func ContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if i := strings.IndexByte(ct, ';'); i >= 0 {
				ct = ct[:i]
			}
			ct = strings.TrimSpace(ct)
			if ct != "" && ct != common.ContentTypeJSON {
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

// Audit records each request to the configured audit sinks.
func Audit(l *audit.Logger, iface string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			outcome := "Executed-Success"
			if sw.status >= 400 {
				outcome = "Failed"
			}
			l.Log(audit.Entry{
				Actor:      r.Header.Get("X-Request-ID"),
				Interface:  iface,
				Function:   r.URL.Path,
				Outcome:    outcome,
				StatusCode: fmt.Sprintf("%d", sw.status),
				RemoteAddr: r.RemoteAddr,
			})
		})
	}
}

// MaxBody limits the size of request bodies.
func MaxBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}
