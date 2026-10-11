// Package es12 implements the SM-DS ES12 handlers used by SM-DP+ (and, via
// ES15, by Alternative SM-DS instances) to register, query and delete events.
package es12

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/common"
	"rsp42/internal/cert"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
)

const maxBody = 1 << 20

// Handler holds the ES12 handler dependencies.
type Handler struct {
	Log    *slog.Logger
	Events *service.EventService
}

// New returns a new ES12 handler.
func New(log *slog.Logger, events *service.EventService) *Handler {
	return &Handler{Log: log, Events: events}
}

// Mount registers the ES12 routes on r.
func Mount(r chi.Router, h *Handler) {
	r.Post("/gsma/rsp2/es12/registerEvent", h.registerEvent)
	r.Post("/gsma/rsp2/es12/deleteEvent", h.deleteEvent)
}

type registerReq struct {
	Header              common.RequestHeader `json:"header"`
	EID                 string               `json:"eid"`
	RSPServerAddress    string               `json:"rspServerAddress"`
	EventID             string               `json:"eventId"`
	ForwardingIndicator bool                 `json:"forwardingIndicator"`
}

func (h *Handler) registerEvent(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := common.ReadJSON(w, r, maxBody, &req); err != nil {
		common.WriteCode(w, rsp.CodeES12BadRequest, "invalid request")
		return
	}
	caller := callerOID(r, req.Header.FunctionRequesterIdentifier)
	err := h.Events.Register(req.EID, req.RSPServerAddress, req.EventID, req.ForwardingIndicator, caller)
	switch {
	case err == nil:
		common.WriteSuccess(w, nil)
	case errors.Is(err, service.ErrEventIDInUse):
		common.WriteCode(w, rsp.CodeEventIDInUse, "EventID already in use")
	default:
		common.WriteCode(w, rsp.CodeES12Upstream, err.Error())
	}
}

type deleteReq struct {
	Header  common.RequestHeader `json:"header"`
	EID     string               `json:"eid"`
	EventID string               `json:"eventId"`
}

func (h *Handler) deleteEvent(w http.ResponseWriter, r *http.Request) {
	var req deleteReq
	if err := common.ReadJSON(w, r, maxBody, &req); err != nil {
		common.WriteCode(w, rsp.CodeES12BadRequest, "invalid request")
		return
	}
	caller := callerOID(r, req.Header.FunctionRequesterIdentifier)
	err := h.Events.Delete(req.EID, req.EventID, caller)
	switch {
	case err == nil:
		common.WriteSuccess(w, nil)
	case errors.Is(err, service.ErrEventNotFound):
		common.WriteCode(w, rsp.CodeEventNotFound, "Event does not exist")
	default:
		common.WriteCode(w, rsp.CodeES12Upstream, err.Error())
	}
}

// callerOID extracts the caller's OID from the mTLS client certificate's
// registered-ID SAN, falling back to the request header identifier (useful in
// tests / non-mTLS deployments).
func callerOID(r *http.Request, fallback string) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if rids, err := cert.RegisteredIDs(r.TLS.PeerCertificates[0]); err == nil && len(rids) > 0 {
			return rids[0]
		}
	}
	if fallback != "" {
		return fallback
	}
	return "unknown"
}
