package admin

import "net/http"

// parsePage reads the shared `?page=`/`?size=` query parameters with the
// management-API defaults and bounds (page >= 1, 1 <= size <= maxPageSize,
// falling back to defaultPageSize).
func parsePage(r *http.Request) (page, size int) {
	q := r.URL.Query()
	page = clampPage(atoiDefault(q.Get("page"), 1))
	size = clampSize(atoiDefault(q.Get("size"), defaultPageSize))
	return page, size
}

// writeListEnvelope writes the shared paginated list body
// `{"items": ..., "page": ..., "size": ..., "total": ...}`.
func writeListEnvelope[T any](w http.ResponseWriter, items T, page, size, total int) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "page": page, "size": size, "total": total,
	})
}
