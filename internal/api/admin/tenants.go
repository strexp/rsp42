package admin

import (
	"errors"
	"net/http"
	"rsp42/internal/api/adminhttp"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/store"
)

type tenantView struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	Status          string             `json:"status"`
	TemplateQuota   *int               `json:"templateQuota,omitempty"`
	ProfileQuota    *int               `json:"profileQuota,omitempty"`
	HasProfileQuota bool               `json:"hasProfileQuota"`
	DefaultUPP      string             `json:"defaultUpp,omitempty"`
	CallbackURL     string             `json:"callbackUrl,omitempty"`
	Usage           *store.TenantUsage `json:"usage,omitempty"`
	CreatedAt       time.Time          `json:"createdAt"`
	UpdatedAt       time.Time          `json:"updatedAt"`
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
	items, err := h.Tenants.List()
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]tenantView, 0, len(items))
	for _, t := range items {
		views = append(views, toTenantView(t))
	}
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
}

func (h *Handler) getTenant(w http.ResponseWriter, r *http.Request) {
	t, err := h.Tenants.Get(chi.URLParam(r, "id"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown tenant")
		return
	}
	v := toTenantView(t)
	if usage, err := h.Tenants.Usage(t.ID); err == nil {
		v.Usage = &usage
	}
	adminhttp.WriteJSON(w, http.StatusOK, v)
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
	var req tenantReq
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	if id := chi.URLParam(r, "id"); id != "" {
		req.ID = id
	}
	if req.ID == "" {
		adminhttp.WriteErr(w, http.StatusBadRequest, "id is required")
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
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "upsertTenant", t.ID, "Executed-Success", req)
	stored, _ := h.Tenants.Get(t.ID)
	adminhttp.WriteJSON(w, http.StatusOK, toTenantView(stored))
}

func (h *Handler) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q := r.URL.Query()
	force := q.Get("force") == "true" || q.Get("force") == "1"

	// N3: deleting a tenant is two-phase. Without force, any referencing
	// resource blocks the deletion and the caller receives the usage counts so
	// the frontend can warn before the operator retries.
	if !force {
		usage, err := h.Tenants.Usage(id)
		if err != nil {
			adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !usage.Empty() {
			// The usage object sits at the top level (N3): the caller reads it
			// to warn before retrying with force.
			adminhttp.WriteJSON(w, http.StatusConflict, map[string]any{
				"code":    "tenant_in_use",
				"message": `tenant still owns resources; pass ?force=true&reassignTo=<tenant|""> to migrate them first`,
				"usage":   usage,
			})
			return
		}
		if err := h.Tenants.Delete(id); err != nil {
			adminhttp.WriteErr(w, http.StatusNotFound, "unknown tenant")
			return
		}
		h.audit(r, "deleteTenant", id, "Executed-Success", nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// force=true: migrate the resources first, then delete. reassignTo="" means
	// the platform-global scope (tenant_id = NULL).
	reassignTo := q.Get("reassignTo")
	if reassignTo == id {
		adminhttp.WriteJSON(w, http.StatusBadRequest, adminhttp.ErrorBody("invalid_request",
			"reassignTo must differ from the tenant being deleted"))
		return
	}
	if reassignTo != "" {
		if _, err := h.Tenants.Get(reassignTo); err != nil {
			adminhttp.WriteJSON(w, http.StatusBadRequest, adminhttp.ErrorBody("unknown_tenant",
				"reassignTo tenant is not registered"))
			return
		}
	}
	if err := h.Tenants.DeleteWithReassign(id, reassignTo); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			adminhttp.WriteErr(w, http.StatusNotFound, "unknown tenant")
			return
		}
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "deleteTenant", id, "Executed-Success", map[string]any{"force": true, "reassignTo": reassignTo})
	w.WriteHeader(http.StatusNoContent)
}
