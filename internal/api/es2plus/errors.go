// Response writers and the error-to-status mapping of the ES2+ surface.

package es2plus

import (
	"errors"
	"net/http"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp/status"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

func writeSuccess(w http.ResponseWriter, extra map[string]any) {
	common.WriteSuccess(w, extra)
}

func writeFailure(w http.ResponseWriter, code status.Code, message string) {
	common.WriteCode(w, code, message)
}

func writeError(w http.ResponseWriter, err error) {
	var te *service.TransitionError
	if errors.As(err, &te) {
		common.WriteCode(w, status.CodeInvalidTransition, err.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		common.WriteCode(w, status.CodeICCIDUnknown, "unknown ICCID")
		return
	}
	common.WriteStatusFailure(w, err)
}
