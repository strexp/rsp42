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
	Tenant    string    `json:"tenant,omitempty"`
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
		Name: t.Name, Tenant: t.TenantID, SAIPMajor: t.SAIPMajor, SAIPMinor: t.SAIPMinor,
		SAIP:   fmt.Sprintf("%d.%d", t.SAIPMajor, t.SAIPMinor),
		SHA256: t.SHA256, Active: t.Active, Size: len(t.Bytes),
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

// scopeTenantParam returns the exact template scope selected by `?tenant=`
// (absent or empty = the platform-global scope).
func scopeTenantParam(r *http.Request) string {
	return r.URL.Query().Get("tenant")
}

func (h *Handler) listUPP(w http.ResponseWriter, r *http.Request) {
	var (
		items []*store.UPPTemplate
		err   error
	)
	if tenantFilter(r) != nil {
		items, err = h.UPP.ListForTenant(scopeTenantParam(r))
	} else {
		items, err = h.UPP.List()
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]uppView, 0, len(items))
	for _, t := range items {
		views = append(views, toUPPView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
}

func (h *Handler) getUPP(w http.ResponseWriter, r *http.Request) {
	t, err := h.UPP.GetScoped(scopeTenantParam(r), chi.URLParam(r, "name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	writeJSON(w, http.StatusOK, toUPPView(t))
}

func (h *Handler) getUPPBytes(w http.ResponseWriter, r *http.Request) {
	t, err := h.UPP.GetScoped(scopeTenantParam(r), chi.URLParam(r, "name"))
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
		Name   string `json:"name"`
		Tenant string `json:"tenant"`
		Data   string `json:"data"` // base64-encoded DER
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "data must be base64-encoded DER")
		return
	}
	// Parse once: the inspection carries the SAIP version and the N13
	// constraint result.
	ins, err := service.InspectUPP(raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid UPP profile: "+err.Error())
		return
	}
	// N13: a template that violates the V2.3.1 structural or semantic
	// constraints must not enter the registry.
	if len(ins.Errors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"code":    "invalid_upp",
			"message": "the SAIP profile violates the V2.3.1 constraints",
			"errors":  ins.Errors,
		})
		return
	}
	major, minor := ins.SAIPMajor, ins.SAIPMinor
	// N16: refuse templates above the configured SAIP baseline. V2.3.1 is a
	// document revision number and is encoded in the package exactly like
	// V2.3, so the comparison only ever uses (major, minor).
	if rej := h.AllowedSAIP.CheckSAIPVersion(major, minor); rej != nil {
		h.writeSAIPVersionErr(w, rej)
		return
	}
	if err := h.checkTemplateQuota(tenant, req.Name); err != nil {
		writeQuotaErr(w, err)
		return
	}
	sum := sha256.Sum256(raw)
	t := &store.UPPTemplate{
		Name: req.Name, TenantID: tenant, SAIPMajor: major, SAIPMinor: minor,
		SHA256: hex.EncodeToString(sum[:]), Bytes: raw, Active: true,
	}
	if err := h.UPP.UpsertArchived(t, "uploaded through the management API"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "putUPP", req.Name, "Executed-Success",
		map[string]any{"tenant": tenant, "saip": fmt.Sprintf("%d.%d", major, minor), "size": len(raw)})
	got, _ := h.UPP.GetScoped(tenant, req.Name)
	writeJSON(w, http.StatusOK, toUPPView(got))
}

// checkTemplateQuota enforces tenants.template_quota when a new tenant template
// is created (replacing an existing one is always allowed).
func (h *Handler) checkTemplateQuota(tenant, name string) error {
	if tenant == "" || h.Tenants == nil {
		return nil
	}
	t, err := h.Tenants.Get(tenant)
	if err != nil || t.TemplateQuota == nil {
		return nil
	}
	if _, err := h.UPP.GetScoped(tenant, name); err == nil {
		return nil // replacement
	}
	n, err := h.UPP.CountForTenant(tenant)
	if err != nil {
		return err
	}
	if n >= *t.TemplateQuota {
		return fmt.Errorf("tenant %q template quota exceeded (%d)", tenant, *t.TemplateQuota)
	}
	return nil
}

func (h *Handler) deleteUPP(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.UPP.Delete(scopeTenantParam(r), name); err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	h.audit(r, "deleteUPP", name, "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setUPPActive(w http.ResponseWriter, r *http.Request, active bool) {
	name := chi.URLParam(r, "name")
	tenant := scopeTenantParam(r)
	if err := h.UPP.SetActive(tenant, name, active); err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	h.audit(r, "setUPPActive", name, "Executed-Success", map[string]any{"tenant": tenant, "active": active})
	got, _ := h.UPP.GetScoped(tenant, name)
	writeJSON(w, http.StatusOK, toUPPView(got))
}

func (h *Handler) activateUPP(w http.ResponseWriter, r *http.Request) {
	h.setUPPActive(w, r, true)
}

func (h *Handler) deactivateUPP(w http.ResponseWriter, r *http.Request) {
	h.setUPPActive(w, r, false)
}
