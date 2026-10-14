// Package api wires the HTTP interfaces of the SM-DP+ and SM-DS processes.
package api

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/es11"
	"rsp42/internal/api/es12"
	"rsp42/internal/api/es2plus"
	"rsp42/internal/api/es9plus"
	"rsp42/internal/api/middleware"
)

// maxBodyBytes bounds request bodies to 1 MiB.
const maxBodyBytes = 1 << 20

// Options configures cross-cutting HTTP behaviour for a router.
type Options struct {
	// CORS lists browser origins allowed to call the interface; empty disables
	// CORS, and a `*` entry allows any origin.
	CORS []string
}

func base(log *slog.Logger, opts Options) chi.Router {
	r := chi.NewRouter()
	if len(opts.CORS) > 0 {
		r.Use(middleware.CORS(opts.CORS))
	}
	r.Use(middleware.RequestID)
	r.Use(middleware.RequestScope)
	r.Use(middleware.Recover(log))
	r.Use(middleware.Logger(log))
	r.Use(middleware.AdminProtocol)
	r.Use(middleware.MaxBody(maxBodyBytes))
	return r
}

// NewES9PRouter builds the SM-DP+ ES9+ (LPA-facing) router.
func NewES9PRouter(log *slog.Logger, h *es9plus.Handler, opts Options) chi.Router {
	r := base(log, opts)
	r.Use(middleware.ContentType)
	es9plus.Mount(r, h)
	return r
}

// NewES2PRouter builds the SM-DP+ ES2+ (Operator-facing) router.
func NewES2PRouter(log *slog.Logger, h *es2plus.Handler, opts Options) chi.Router {
	r := base(log, opts)
	r.Use(middleware.ContentType)
	es2plus.Mount(r, h)
	return r
}

// NewES11Router builds the SM-DS ES11 (LPA-facing) router.
func NewES11Router(log *slog.Logger, h *es11.Handler, opts Options) chi.Router {
	r := base(log, opts)
	r.Use(middleware.ContentType)
	es11.Mount(r, h)
	return r
}

// NewES12Router builds the SM-DS ES12 (SM-DP+/SM-DS-facing) router.
func NewES12Router(log *slog.Logger, h *es12.Handler, opts Options) chi.Router {
	r := base(log, opts)
	r.Use(middleware.ContentType)
	es12.Mount(r, h)
	return r
}

// NewAdminRouter builds the shared admin router exposing health endpoints and,
// when register is non-nil, the management API.
func NewAdminRouter(log *slog.Logger, ready func() bool, register func(chi.Router), opts Options) chi.Router {
	r := base(log, opts)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	r.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if ready != nil && !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	if register != nil {
		register(r)
	}
	return r
}
