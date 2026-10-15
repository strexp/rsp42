// Route registration for the ES2+ interface.

package es2plus

import (
	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/middleware"
)

// Mount registers the ES2+ routes on r.
func Mount(r chi.Router, h *Handler) {
	idem := middleware.Idempotency(h.Idem)
	r.Post("/gsma/rsp2/es2plus/downloadOrder", h.downloadOrder)
	r.With(idem).Post("/gsma/rsp2/es2plus/confirmOrder", h.confirmOrder)
	r.With(idem).Post("/gsma/rsp2/es2plus/cancelOrder", h.cancelOrder)
	r.With(idem).Post("/gsma/rsp2/es2plus/releaseProfile", h.releaseProfile)
	r.Post("/gsma/rsp2/es2plus/handleDownloadProgressInfo", h.handleDownloadProgressInfo)
	r.Post("/gsma/rsp2/es2plus/handleAcrRequest", h.handleAcrRequest)
}
