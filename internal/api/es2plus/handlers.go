// Package es2plus implements the SM-DP+ ES2+ server handlers, the outbound
// callback client, and the ES2+ client library used by operator systems.
package es2plus

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"rsp42/internal/api/common"
	"rsp42/internal/rsp"
	"rsp42/internal/service"
	"rsp42/internal/store"
)

// OrderAuditor records ES2+ order actions.
type OrderAuditor interface {
	Insert(iccid, eid, matchingID, action, requestJSON, resultJSON string) error
}

// Handler holds the ES2+ handler dependencies.
type Handler struct {
	Log       *slog.Logger
	Profiles  service.ProfileStore
	Orders    *service.OrderService
	Inventory *service.Inventory
	// OrderAudit, when set, records each order action.
	OrderAudit OrderAuditor
	// ACRHandler, when set, is invoked for handleAcrRequest.
	ACRHandler func(req AcrRequest) (*AcrResponse, error)
	// Registrar, when set, registers an SM-DS event on ConfirmOrder.
	Registrar *service.Registrar
}

// New returns a new ES2+ handler.
func New(log *slog.Logger, profiles service.ProfileStore, orders *service.OrderService, inv *service.Inventory) *Handler {
	return &Handler{Log: log, Profiles: profiles, Orders: orders, Inventory: inv}
}

// Mount registers the ES2+ routes on r.
func Mount(r chi.Router, h *Handler) {
	r.Post("/gsma/rsp2/es2plus/downloadOrder", h.downloadOrder)
	r.Post("/gsma/rsp2/es2plus/confirmOrder", h.confirmOrder)
	r.Post("/gsma/rsp2/es2plus/cancelOrder", h.cancelOrder)
	r.Post("/gsma/rsp2/es2plus/releaseProfile", h.releaseProfile)
	r.Post("/gsma/rsp2/es2plus/handleDownloadProgressInfo", h.handleDownloadProgressInfo)
	r.Post("/gsma/rsp2/es2plus/handleAcrRequest", h.handleAcrRequest)
}

// Request types -------------------------------------------------------------

type downloadOrderReq struct {
	Header      common.RequestHeader `json:"header"`
	EID         string               `json:"eid"`
	ICCID       string               `json:"iccid"`
	ProfileType string               `json:"profileType"`
}

type confirmOrderReq struct {
	Header           common.RequestHeader `json:"header"`
	ICCID            string               `json:"iccid"`
	EID              string               `json:"eid"`
	MatchingID       string               `json:"matchingId"`
	ConfirmationCode string               `json:"confirmationCode"`
	SMDSAddress      string               `json:"smdsAddress"`
	ReleaseFlag      bool                 `json:"releaseFlag"`
}

type cancelOrderReq struct {
	Header                      common.RequestHeader `json:"header"`
	ICCID                       string               `json:"iccid"`
	EID                         string               `json:"eid"`
	MatchingID                  string               `json:"matchingId"`
	FinalProfileStatusIndicator string               `json:"finalProfileStatusIndicator"`
}

type releaseProfileReq struct {
	Header common.RequestHeader `json:"header"`
	ICCID  string               `json:"iccid"`
}

// AcrRequest / AcrResponse are the confirm/ACR hooks (Phase 10 supplies these).
type AcrRequest struct {
	EID   string          `json:"eid"`
	ICCID string          `json:"iccid"`
	Data  json.RawMessage `json:"-"`
}

// AcrResponse is the operator's response to handleAcrRequest.
type AcrResponse struct {
	Header common.HeaderResponse `json:"header"`
}

// Handlers ------------------------------------------------------------------

func (h *Handler) downloadOrder(w http.ResponseWriter, r *http.Request) {
	var req downloadOrderReq
	if !decode(w, r, &req) {
		return
	}
	p, err := h.Inventory.Allocate(req.EID, req.ProfileType, req.ICCID)
	if err != nil {
		writeFailure(w, rsp.CodeAllocateFailed, err.Error())
		return
	}
	if err := h.record("downloadOrder", req.ICCID, req.EID, "", req); err != nil {
		h.Log.Warn("order record", "err", err)
	}
	writeSuccess(w, map[string]any{"iccid": p.ICCID})
}

func (h *Handler) confirmOrder(w http.ResponseWriter, r *http.Request) {
	var req confirmOrderReq
	if !decode(w, r, &req) {
		return
	}
	if req.ICCID == "" {
		writeFailure(w, rsp.CodeProfileNotFound, "iccid is required")
		return
	}
	p, err := h.Profiles.GetByICCID(normalizeICCID(req.ICCID))
	if err != nil {
		writeFailure(w, rsp.CodeProfileNotFound, "unknown ICCID")
		return
	}
	if req.EID != "" {
		p.EID = req.EID
	}
	matchingID := req.MatchingID
	if matchingID == "" {
		matchingID = "MATCH-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	}
	p.MatchingID = matchingID
	if req.SMDSAddress != "" {
		p.SMDSAddress = req.SMDSAddress
	}
	if req.ConfirmationCode != "" {
		sum := sha256.Sum256([]byte(req.ConfirmationCode))
		p.CCHash = sum[:]
		p.CCRequired = true
	}
	if err := h.Profiles.Update(p); err != nil {
		writeFailure(w, rsp.CodeProfileUpdateFailed, err.Error())
		return
	}
	if _, err := h.Orders.Confirm(p.ICCID, req.ReleaseFlag); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record("confirmOrder", p.ICCID, p.EID, matchingID, req)
	if req.SMDSAddress != "" && h.Registrar != nil && p.EID != "" {
		if err := h.Registrar.Register(p.EID, matchingID, req.SMDSAddress); err != nil {
			h.Log.Warn("ES12 register event", "eid", p.EID, "err", err)
		}
	}
	writeSuccess(w, map[string]any{"matchingId": matchingID, "smdpAddress": ""})
}

func (h *Handler) cancelOrder(w http.ResponseWriter, r *http.Request) {
	var req cancelOrderReq
	if !decode(w, r, &req) {
		return
	}
	final, err := parseFinalStatus(req.FinalProfileStatusIndicator)
	if err != nil {
		writeFailure(w, rsp.CodeInputRefused, err.Error())
		return
	}
	if _, err := h.Orders.Cancel(normalizeICCID(req.ICCID), final == finalUnavailable); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record("cancelOrder", req.ICCID, req.EID, req.MatchingID, req)
	writeSuccess(w, nil)
}

// finalProfileStatusIndicator values (SGP.22 Table 29).
const (
	finalAvailable   = "Available"
	finalUnavailable = "Unavailable"
)

// parseFinalStatus maps the ES2+ finalProfileStatusIndicator to its canonical
// form. Table 29 defines exactly two values; a missing or unknown value is
// refused (CancelOrder is specified to return Failed with a relevant status
// code, e.g. 8.2.1/1.2).
func parseFinalStatus(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "available":
		return finalAvailable, nil
	case "unavailable":
		return finalUnavailable, nil
	default:
		return "", fmt.Errorf("invalid finalProfileStatusIndicator %q (want Available|Unavailable)", s)
	}
}

func (h *Handler) releaseProfile(w http.ResponseWriter, r *http.Request) {
	var req releaseProfileReq
	if !decode(w, r, &req) {
		return
	}
	if _, err := h.Orders.Release(normalizeICCID(req.ICCID)); err != nil {
		writeError(w, err)
		return
	}
	_ = h.record("releaseProfile", req.ICCID, "", "", req)
	writeSuccess(w, nil)
}

func (h *Handler) handleDownloadProgressInfo(w http.ResponseWriter, _ *http.Request) {
	// Notification function: always HTTP 204.
	common.WriteNoContent(w)
}

func (h *Handler) handleAcrRequest(w http.ResponseWriter, r *http.Request) {
	body, err := common.ReadRaw(w, r, 1<<20)
	if err != nil {
		common.WriteCode(w, rsp.CodeInputRefused, "cannot read body")
		return
	}
	if h.ACRHandler == nil {
		http.Error(w, "handleAcrRequest not implemented", http.StatusNotImplemented)
		return
	}
	var req AcrRequest
	_ = json.Unmarshal(body, &req)
	req.Data = body
	resp, err := h.ACRHandler(req)
	if err != nil {
		common.WriteCode(w, rsp.CodeInputRefused, err.Error())
		return
	}
	if resp == nil {
		resp = &AcrResponse{Header: common.NewSuccess()}
	}
	common.WriteJSON(w, resp)
}

// Helpers -------------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := common.ReadJSON(w, r, 1<<20, v); err != nil {
		common.WriteCode(w, rsp.CodeInvalidRequest, "invalid JSON")
		return false
	}
	// ES2+ requires both header identifiers.
	var hdr common.RequestHeader
	switch t := v.(type) {
	case *downloadOrderReq:
		hdr = t.Header
	case *confirmOrderReq:
		hdr = t.Header
	case *cancelOrderReq:
		hdr = t.Header
	case *releaseProfileReq:
		hdr = t.Header
	}
	if hdr.FunctionRequesterIdentifier == "" || hdr.FunctionCallIdentifier == "" {
		common.WriteCode(w, rsp.CodeInvalidRequest, "missing header.functionRequesterIdentifier/functionCallIdentifier")
		return false
	}
	return true
}

func (h *Handler) record(action, iccid, eid, matchingID string, req any) error {
	if h.OrderAudit == nil {
		return nil
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return h.OrderAudit.Insert(iccid, eid, matchingID, action, string(raw), "")
}

func writeSuccess(w http.ResponseWriter, extra map[string]any) {
	common.WriteSuccess(w, extra)
}

func writeFailure(w http.ResponseWriter, code rsp.Code, message string) {
	common.WriteCode(w, code, message)
}

func writeError(w http.ResponseWriter, err error) {
	var te *service.TransitionError
	if errors.As(err, &te) {
		common.WriteCode(w, rsp.CodeInvalidTransition, err.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		common.WriteCode(w, rsp.CodeProfileNotFound, "unknown ICCID")
		return
	}
	common.WriteStatusFailure(w, err)
}

// normalizeICCID strips a trailing F padding so DB lookups match 19/20-digit
// inputs.
func normalizeICCID(iccid string) string {
	return strings.TrimRight(iccid, "fF")
}
