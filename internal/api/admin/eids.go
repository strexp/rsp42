package admin

import (
	"net/http"
)

// listEIDs aggregates the inventory by eUICC (EID), which is what a platform
// dashboard needs to answer "which devices hold which profiles" (G16).
func (h *Handler) listEIDs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, size := parsePage(r)
	filter := profileFilterFromQuery(q)
	items, total, err := h.Profiles.ListEIDs(filter, size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeListEnvelope(w, items, page, size, total)
}
