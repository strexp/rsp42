package admin

import (
	"net/http"
)

// listEIDs aggregates the inventory by eUICC (EID), which is what a platform
// dashboard needs to answer "which devices hold which profiles" (G16).
func (h *Handler) listEIDs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := clampSize(atoiDefault(q.Get("size"), defaultPageSize))
	page := clampPage(atoiDefault(q.Get("page"), 1))
	filter := profileFilterFromQuery(q)
	items, total, err := h.Profiles.ListEIDs(filter, size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "page": page, "size": size, "total": total})
}
