// ES2+.HandleDownloadProgressInfo (§5.3.6): a notification function.

package es2plus

import (
	"net/http"

	"rsp42/internal/api/common"
)

func (h *Handler) handleDownloadProgressInfo(w http.ResponseWriter, _ *http.Request) {
	// Notification function: always HTTP 204.
	common.WriteNoContent(w)
}
