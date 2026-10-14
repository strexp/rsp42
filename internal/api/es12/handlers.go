// Package es12 implements the SM-DS ES12 handlers used by SM-DP+ (and, via
// ES15, by Alternative SM-DS instances) to register, query and delete events.
package es12

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/common"
	"rsp42/internal/cert"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// AuditWriter records protocol-level ES12 failures. It is defined here so the
// handler does not depend on the concrete SQLite repository.
type AuditWriter interface {
	Insert(e *store.AuditEntry) error
}

// Handler holds the ES12 handler dependencies.
type Handler struct {
	Log    *slog.Logger
	Events *service.EventService
	// Tenants optionally maps a caller OID to a tenant when the correlation
	// header is absent.
	Tenants *service.TenantResolver
	// Audit, when set, records protocol-level ES12 failures (ES12 answers HTTP
	// 200 with a Failed status, so the shared audit middleware cannot see them).
	Audit AuditWriter
}

// New returns a new ES12 handler.
func New(log *slog.Logger, events *service.EventService) *Handler {
	return &Handler{Log: log, Events: events}
}

// eventMeta resolves the correlation metadata of an ES12 request: the explicit
// headers win, otherwise the caller OID mapping applies.
func (h *Handler) eventMeta(r *http.Request, caller string) service.EventMeta {
	meta := service.EventMetaFromHeaders(r.Header)
	if meta.Tenant == "" {
		if tenant, ok := h.Tenants.Resolve(caller); ok {
			meta.Tenant = tenant
		}
	}
	common.SetActor(r.Context(), caller)
	common.SetTenant(r.Context(), meta.Tenant)
	return meta
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
	if err := common.ReadJSON(w, r, 0, &req); err != nil {
		common.WriteCode(w, rsp.CodeES12BadRequest, "invalid request")
		return
	}
	caller := callerOID(r, req.Header.FunctionRequesterIdentifier)
	meta := h.eventMeta(r, caller)
	err := h.Events.Register(req.EID, req.RSPServerAddress, req.EventID, req.ForwardingIndicator, caller, meta)
	switch {
	case err == nil:
		common.WriteSuccess(w, nil)
	case errors.Is(err, service.ErrEventIDInUse):
		h.auditFailure(meta.Tenant, "registerEvent", req.EID, "8.9.5/3.3", err)
		common.WriteCode(w, rsp.CodeEventIDInUse, "EventID already in use")
	default:
		h.auditFailure(meta.Tenant, "registerEvent", req.EID, "8.9/5.1", err)
		common.WriteCode(w, rsp.CodeES12Upstream, err.Error())
	}
}

// auditFailure records a protocol-level ES12 failure.
func (h *Handler) auditFailure(tenant, function, subject, code string, err error) {
	if h.Audit == nil {
		return
	}
	detail, _ := json.Marshal(map[string]string{"error": err.Error(), "statusCode": code})
	_ = h.Audit.Insert(&store.AuditEntry{
		TenantID: tenant, Interface: "es12", Function: function, Subject: subject,
		Outcome: "Failed", StatusCode: code, DetailJSON: string(detail),
	})
}

type deleteReq struct {
	Header  common.RequestHeader `json:"header"`
	EID     string               `json:"eid"`
	EventID string               `json:"eventId"`
}

func (h *Handler) deleteEvent(w http.ResponseWriter, r *http.Request) {
	var req deleteReq
	if err := common.ReadJSON(w, r, 0, &req); err != nil {
		common.WriteCode(w, rsp.CodeES12BadRequest, "invalid request")
		return
	}
	caller := callerOID(r, req.Header.FunctionRequesterIdentifier)
	h.eventMeta(r, caller)
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
