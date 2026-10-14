package admin

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/store"
)

type tenantView struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Status          string    `json:"status"`
	TemplateQuota   *int      `json:"templateQuota,omitempty"`
	ProfileQuota    *int      `json:"profileQuota,omitempty"`
	HasProfileQuota bool      `json:"hasProfileQuota"`
	DefaultUPP      string    `json:"defaultUpp,omitempty"`
	CallbackURL     string    `json:"callbackUrl,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func toTenantView(t *store.Tenant) tenantView {
	return tenantView{
		ID: t.ID, Name: t.Name, Status: t.Status,
		TemplateQuota: t.TemplateQuota, ProfileQuota: t.ProfileQuota,
		HasProfileQuota: t.ProfileQuota != nil,
		DefaultUPP:      t.DefaultUPP, CallbackURL: t.CallbackURL,
		CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
	}
}

func (h *Handler) listTenants(w http.ResponseWriter, _ *http.Request) {
	if h.Tenants == nil {
		writeErr(w, http.StatusNotImplemented, "tenant registry not configured")
		return
	}
	items, err := h.Tenants.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]tenantView, 0, len(items))
	for _, t := range items {
		views = append(views, toTenantView(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
}

func (h *Handler) getTenant(w http.ResponseWriter, r *http.Request) {
	if h.Tenants == nil {
		writeErr(w, http.StatusNotImplemented, "tenant registry not configured")
		return
	}
	t, err := h.Tenants.Get(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown tenant")
		return
	}
	writeJSON(w, http.StatusOK, toTenantView(t))
}

type tenantReq struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Status        string `json:"status"`
	TemplateQuota *int   `json:"templateQuota"`
	ProfileQuota  *int   `json:"profileQuota"`
	DefaultUPP    string `json:"defaultUpp"`
	CallbackURL   string `json:"callbackUrl"`
}

func (h *Handler) upsertTenant(w http.ResponseWriter, r *http.Request) {
	if h.Tenants == nil {
		writeErr(w, http.StatusNotImplemented, "tenant registry not configured")
		return
	}
	var req tenantReq
	if !readJSON(w, r, &req) {
		return
	}
	if id := chi.URLParam(r, "id"); id != "" {
		req.ID = id
	}
	if req.ID == "" {
		writeErr(w, http.StatusBadRequest, "id is required")
		return
	}
	// A PATCH-style update keeps the existing values for omitted fields.
	existing, err := h.Tenants.Get(req.ID)
	if err != nil {
		existing = nil
	}
	t := &store.Tenant{
		ID: req.ID, Name: req.Name, Status: req.Status,
		TemplateQuota: req.TemplateQuota, ProfileQuota: req.ProfileQuota,
		DefaultUPP: req.DefaultUPP, CallbackURL: req.CallbackURL,
	}
	if existing != nil {
		t.CreatedAt = existing.CreatedAt
		if t.Name == "" {
			t.Name = existing.Name
		}
		if t.Status == "" {
			t.Status = existing.Status
		}
		if t.TemplateQuota == nil {
			t.TemplateQuota = existing.TemplateQuota
		}
		if t.ProfileQuota == nil {
			t.ProfileQuota = existing.ProfileQuota
		}
		if t.DefaultUPP == "" {
			t.DefaultUPP = existing.DefaultUPP
		}
		if t.CallbackURL == "" {
			t.CallbackURL = existing.CallbackURL
		}
	}
	if t.Name == "" {
		t.Name = t.ID
	}
	if t.Status == "" {
		t.Status = store.TenantActive
	}
	if err := h.Tenants.Upsert(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "upsertTenant", t.ID, "Executed-Success", req)
	stored, _ := h.Tenants.Get(t.ID)
	writeJSON(w, http.StatusOK, toTenantView(stored))
}

func (h *Handler) deleteTenant(w http.ResponseWriter, r *http.Request) {
	if h.Tenants == nil {
		writeErr(w, http.StatusNotImplemented, "tenant registry not configured")
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.Tenants.Delete(id); err != nil {
		writeErr(w, http.StatusNotFound, "unknown tenant")
		return
	}
	h.audit(r, "deleteTenant", id, "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}
