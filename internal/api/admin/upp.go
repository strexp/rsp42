package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/service"
	"rsp42/internal/store"
)

type uppView struct {
	Name      string    `json:"name"`
	SAIPMajor int       `json:"saipMajor"`
	SAIPMinor int       `json:"saipMinor"`
	SAIP      string    `json:"saip"`
	SHA256    string    `json:"sha256"`
	Active    bool      `json:"active"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func toUPPView(t *store.UPPTemplate) uppView {
	return uppView{
		Name: t.Name, SAIPMajor: t.SAIPMajor, SAIPMinor: t.SAIPMinor,
		SAIP:   fmt.Sprintf("%d.%d", t.SAIPMajor, t.SAIPMinor),
		SHA256: t.SHA256, Active: t.Active, Size: len(t.Bytes),
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

func (h *Handler) listUPP(w http.ResponseWriter, _ *http.Request) {
	items, err := h.UPP.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]uppView, 0, len(items))
	for _, t := range items {
		views = append(views, toUPPView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views})
}

func (h *Handler) getUPP(w http.ResponseWriter, r *http.Request) {
	t, err := h.UPP.GetByName(chi.URLParam(r, "name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	writeJSON(w, http.StatusOK, toUPPView(t))
}

func (h *Handler) getUPPBytes(w http.ResponseWriter, r *http.Request) {
	t, err := h.UPP.GetByName(chi.URLParam(r, "name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(t.Bytes)
}

func (h *Handler) putUPP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Data string `json:"data"` // base64-encoded DER
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "data must be base64-encoded DER")
		return
	}
	major, minor, err := service.UPPVersion(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid UPP profile: "+err.Error())
		return
	}
	sum := sha256.Sum256(raw)
	t := &store.UPPTemplate{
		Name: req.Name, SAIPMajor: major, SAIPMinor: minor,
		SHA256: hex.EncodeToString(sum[:]), Bytes: raw, Active: true,
	}
	if err := h.UPP.Upsert(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "putUPP", req.Name, "Executed-Success", map[string]any{"saip": fmt.Sprintf("%d.%d", major, minor), "size": len(raw)})
	got, _ := h.UPP.GetByName(req.Name)
	writeJSON(w, http.StatusOK, toUPPView(got))
}

func (h *Handler) deleteUPP(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.UPP.Delete(name); err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	h.audit(r, "deleteUPP", name, "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setUPPActive(w http.ResponseWriter, r *http.Request, active bool) {
	name := chi.URLParam(r, "name")
	if err := h.UPP.SetActive(name, active); err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	h.audit(r, "setUPPActive", name, "Executed-Success", map[string]any{"active": active})
	got, _ := h.UPP.GetByName(name)
	writeJSON(w, http.StatusOK, toUPPView(got))
}

func (h *Handler) activateUPP(w http.ResponseWriter, r *http.Request) {
	h.setUPPActive(w, r, true)
}

func (h *Handler) deactivateUPP(w http.ResponseWriter, r *http.Request) {
	h.setUPPActive(w, r, false)
}
