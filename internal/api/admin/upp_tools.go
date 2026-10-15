package admin

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/api/adminhttp"
	"rsp42/internal/saip/personalization"
	"rsp42/internal/store"
	"rsp42/internal/uppinspect"
)

// uppSchema returns the personalization field catalog (G7).
func (h *Handler) uppSchema(w http.ResponseWriter, r *http.Request) {
	t, err := h.UPP.GetScoped(scopeTenantParam(r), chi.URLParam(r, "name"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown template")
		return
	}
	ins, err := uppinspect.InspectUPP(t.Bytes)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusUnprocessableEntity, "invalid UPP: "+err.Error())
		return
	}
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{
		"template":   toUPPView(t),
		"inspection": ins,
		"fields":     uppinspect.PersonalizationFields(ins),
	})
}

// validateUPP parses an uploaded SAIP binary and reports its structure and
// consistency warnings without storing anything (G7).
func (h *Handler) validateUPP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Data string `json:"data"` // base64 DER
	}
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusBadRequest, "data must be base64-encoded DER")
		return
	}
	ins, err := uppinspect.InspectUPP(raw)
	if err != nil {
		adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	// N16: uploading a template just to look at its structure stays possible,
	// but a version above the baseline is reported explicitly so the caller
	// learns now rather than at POST /upp time. N13 hard constraint violations
	// make the package invalid (valid: false) and are listed under errors[].
	warnings := append([]string{}, ins.Warnings...)
	if rej := checkSAIPVersion(h.AllowedSAIP, ins.SAIPMajor, ins.SAIPMinor); rej != nil {
		warnings = append(warnings, rej.Error())
	}
	errors := ins.Errors
	if errors == nil {
		errors = []string{}
	}
	h.audit(r, "validateUPP", req.Name, "Executed-Success", map[string]any{"sha256": ins.SHA256, "saip": ins.SAIP})
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{
		"valid": len(errors) == 0, "inspection": ins, "warnings": warnings, "errors": errors,
	})
}

// renderUPP is a dry-run: it applies personalization to a template and reports
// the result (digest, size, structure) without allocating or storing anything
// (G7).
func (h *Handler) renderUPP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Tenant string `json:"tenant"`
		// Data is an alternative to Name: a base64 DER template that is
		// rendered ad hoc without being stored (N5, for the upload wizard).
		Data string `json:"data"`
		persoReq
	}
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	var (
		raw     []byte
		tplView *uppView
	)
	switch {
	case req.Name != "" && req.Data != "":
		adminhttp.WriteJSON(w, http.StatusBadRequest, adminhttp.ErrorBody("invalid_request", "name and data are mutually exclusive"))
		return
	case req.Name != "":
		tpl, err := h.UPP.GetForTenant(tenant, req.Name)
		if err != nil {
			adminhttp.WriteErr(w, http.StatusNotFound, "unknown template "+req.Name)
			return
		}
		raw = tpl.Bytes
		v := toUPPView(tpl)
		tplView = &v
	case req.Data != "":
		raw, err = base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			adminhttp.WriteErr(w, http.StatusBadRequest, "data must be base64-encoded DER")
			return
		}
	default:
		adminhttp.WriteJSON(w, http.StatusBadRequest, adminhttp.ErrorBody("invalid_request", "name or data is required"))
		return
	}
	data, err := req.toData("")
	if err != nil {
		adminhttp.WriteErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ins, encoded, err := uppinspect.RenderUPP(raw, data, &personalization.Engine{})
	if err != nil {
		adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"rendered": false, "error": err.Error()})
		return
	}
	// The ad-hoc path never stores anything; the audit subject marks it.
	subject := req.Name
	if subject == "" {
		subject = "<ad-hoc>"
	}
	h.audit(r, "renderUPP", subject, "Executed-Success", map[string]any{"bytes": len(encoded)})
	resp := map[string]any{
		"rendered":   true,
		"inspection": ins,
		"bytes":      len(encoded),
	}
	if tplView != nil {
		resp["template"] = *tplView
	} else {
		resp["template"] = map[string]any{"name": "<ad-hoc>"}
	}
	adminhttp.WriteJSON(w, http.StatusOK, resp)
}

// cloneUPP derives a tenant template from a global one (G7).
func (h *Handler) cloneUPP(w http.ResponseWriter, r *http.Request) {
	source := chi.URLParam(r, "name")
	var req struct {
		Tenant string `json:"tenant"`
		Name   string `json:"name"`
	}
	if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	tenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	if tenant == "" {
		adminhttp.WriteErr(w, http.StatusBadRequest, "tenant is required for a clone (use promote to make a global template)")
		return
	}
	src, err := h.UPP.GetForTenant(tenant, source)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown template "+source)
		return
	}
	if rej := checkSAIPVersion(h.AllowedSAIP, src.SAIPMajor, src.SAIPMinor); rej != nil {
		h.writeSAIPVersionErr(w, rej)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = source
	}
	if err := h.checkTemplateQuota(tenant, name); err != nil {
		writeQuotaErr(w, err)
		return
	}
	dst := &store.UPPTemplate{
		Name: name, TenantID: tenant, SAIPMajor: src.SAIPMajor, SAIPMinor: src.SAIPMinor,
		SHA256: src.SHA256, Bytes: src.Bytes, Active: true,
	}
	if err := h.UPP.Upsert(dst); err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "cloneUPP", name, "Executed-Success", map[string]any{"from": source, "tenant": tenant})
	got, _ := h.UPP.GetScoped(tenant, name)
	adminhttp.WriteJSON(w, http.StatusCreated, toUPPView(got))
}

// promoteUPP promotes a tenant template to the platform-global scope (G7).
func (h *Handler) promoteUPP(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	tenant := scopeTenantParam(r)
	if tenant == "" {
		adminhttp.WriteErr(w, http.StatusBadRequest, "tenant is required (only a tenant template can be promoted)")
		return
	}
	src, err := h.UPP.GetScoped(tenant, name)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown template")
		return
	}
	if rej := checkSAIPVersion(h.AllowedSAIP, src.SAIPMajor, src.SAIPMinor); rej != nil {
		h.writeSAIPVersionErr(w, rej)
		return
	}
	if _, err := h.UPP.GetScoped("", name); err == nil && r.URL.Query().Get("overwrite") != "1" {
		adminhttp.WriteErr(w, http.StatusConflict, fmt.Sprintf("a global template named %q already exists (pass overwrite=1 to replace it)", name))
		return
	}
	dst := &store.UPPTemplate{
		Name: name, TenantID: "", SAIPMajor: src.SAIPMajor, SAIPMinor: src.SAIPMinor,
		SHA256: src.SHA256, Bytes: src.Bytes, Active: true,
	}
	if err := h.UPP.Upsert(dst); err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "promoteUPP", name, "Executed-Success", map[string]any{"tenant": tenant})
	got, _ := h.UPP.GetScoped("", name)
	adminhttp.WriteJSON(w, http.StatusOK, toUPPView(got))
}

// uppVersionView is the API representation of an archived template revision.
type uppVersionView struct {
	ID        int64     `json:"id"`
	Tenant    string    `json:"tenant,omitempty"`
	Name      string    `json:"name"`
	VersionNo int       `json:"versionNo"`
	SAIP      string    `json:"saip"`
	SHA256    string    `json:"sha256"`
	Size      int       `json:"size"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// listUPPVersions returns the archived revisions of a template (G18).
func (h *Handler) listUPPVersions(w http.ResponseWriter, r *http.Request) {
	tenant := scopeTenantParam(r)
	name := chi.URLParam(r, "name")
	items, err := h.UPP.ListVersions(tenant, name)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]uppVersionView, 0, len(items))
	for _, v := range items {
		views = append(views, uppVersionView{
			ID: v.ID, Tenant: v.TenantID, Name: v.Name, VersionNo: v.VersionNo,
			SAIP: fmt.Sprintf("%d.%d", v.SAIPMajor, v.SAIPMinor), SHA256: v.SHA256,
			Size: len(v.Bytes), Note: v.Note, CreatedAt: v.CreatedAt,
		})
	}
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
}

// restoreUPP rolls a template back to an archived revision. The revision being
// replaced is archived in turn, so a rollback is itself reversible.
func (h *Handler) restoreUPP(w http.ResponseWriter, r *http.Request) {
	tenant := scopeTenantParam(r)
	name := chi.URLParam(r, "name")
	id, err := adminhttp.ParseID(chi.URLParam(r, "version"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusBadRequest, "invalid version id")
		return
	}
	v, err := h.UPP.GetVersion(tenant, name, id)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusNotFound, "unknown template version")
		return
	}
	if rej := checkSAIPVersion(h.AllowedSAIP, v.SAIPMajor, v.SAIPMinor); rej != nil {
		h.writeSAIPVersionErr(w, rej)
		return
	}
	tpl := &store.UPPTemplate{
		Name: name, TenantID: tenant, SAIPMajor: v.SAIPMajor, SAIPMinor: v.SAIPMinor,
		SHA256: v.SHA256, Bytes: v.Bytes, Active: true,
	}
	if err := h.UPP.UpsertArchived(tpl, "restore of version "+strconv.FormatInt(id, 10)); err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "restoreUPP", name, "Executed-Success", map[string]any{"tenant": tenant, "versionId": id})
	got, _ := h.UPP.GetScoped(tenant, name)
	adminhttp.WriteJSON(w, http.StatusOK, toUPPView(got))
}
