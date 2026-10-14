package admin

import (
	"net/http"
	"rsp42/internal/api/adminhttp"
)

// listEIDs aggregates the inventory by eUICC (EID), which is what a platform
// dashboard needs to answer "which devices hold which profiles" (G16).
func (h *Handler) listEIDs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, size := adminhttp.ParsePage(r)
	filter := profileFilterFromQuery(q)
	items, total, err := h.Profiles.ListEIDs(filter, size, (page-1)*size)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	adminhttp.WriteListEnvelope(w, items, page, size, total)
}
