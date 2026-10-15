// Caller identity, tenant resolution and the authorisation checks shared by the
// order functions.

package es2plus

import (
	"net/http"
	"strings"

	"rsp42/internal/api/common"
	"rsp42/internal/iccid"
	"rsp42/internal/rsp/status"
	"rsp42/internal/store"
)

// applyCaller records the caller identity in the audit scope and resolves the
// tenant from functionRequesterIdentifier.
//
// An unmapped requester falls back to the platform-default tenant (""), and the
// fallback is recorded on the audit row (`warning=unmapped`, plus the requester
// and the resolved tenant) and counted in
// rsp42_es2p_tenant_unmapped_total, so an operator health check can alert on a
// carrier that was never registered (docs/esim42-integration-gaps.md §2.3). With
// an empty requester_tenants table nothing is flagged: a single-tenant
// deployment has nothing to map.
func (h *Handler) applyCaller(r *http.Request, hdr common.RequestHeader) string {
	ctx := r.Context()
	common.SetActor(ctx, hdr.FunctionRequesterIdentifier)
	tenant, mapped := h.resolveRequester(hdr.FunctionRequesterIdentifier)
	if !mapped {
		tenant = ""
		if h.requesterCount() > 0 {
			common.AddDetail(ctx, "warning", "unmapped")
			common.AddDetail(ctx, "requester", hdr.FunctionRequesterIdentifier)
			if h.Metrics != nil {
				h.Metrics.Inc("rsp42_es2p_tenant_unmapped_total", nil)
			}
			if h.Log != nil {
				h.Log.Warn("unmapped ES2+ functionRequesterIdentifier; using the platform default tenant",
					"requester", hdr.FunctionRequesterIdentifier)
			}
		}
	}
	common.SetTenant(ctx, tenant)
	return tenant
}

// resolveProfileType interprets the operator's profileType. A
// "<tenant>/<template>" value selects a template inside the caller's tenant
// (SGP.22 §6.5.2.1: profileType is content free information defined by the
// Operator). The second return value reports whether the value carried the
// selector; anything else stays opaque and lets the SM-DP+ fall back to the
// eUICC version and the tenant default, but the caller records it (C2).
//
// An empty tenant part ("/<template>") names a template owned by the
// platform-default tenant, i.e. a global template (including one promoted with
// POST /upp/{name}/promote). That is the only way to select such a template: a
// caller mapped to a carrier has no prefix that denotes the platform-default
// owner. The name is still resolved with the caller's scope, so a tenant only
// ever reaches its own template or a global one.
func (h *Handler) resolveProfileType(tenant, profileType string) (string, bool, error) {
	i := strings.IndexByte(profileType, '/')
	if i < 0 {
		return "", false, nil
	}
	want, name := profileType[:i], profileType[i+1:]
	if name == "" {
		return "", false, status.CodeProfileTypeUnknown.Status("malformed profileType " + profileType)
	}
	if want != "" && want != tenant {
		return "", false, status.CodeProfileTypeNotAllowed.Status("profileType belongs to another tenant")
	}
	if h.UPP != nil {
		if _, err := h.UPP.GetForTenant(tenant, name); err != nil {
			return "", false, status.CodeProfileTypeUnknown.Status("unknown profileType template " + name)
		}
	}
	return name, true, nil
}

// authorize enforces tenant ownership of a profile and, when the request
// carries an EID, the EID consistency required by SGP.22 §5.3.2.
func (h *Handler) authorize(tenant string, p *store.Profile, eid string) error {
	if p.TenantID != tenant {
		return status.CodeInputRefused.Status("ICCID belongs to another tenant")
	}
	if eid != "" && p.EID != "" && p.EID != eid {
		return status.CodeInvalidAssociation.Status("eid does not match the download order")
	}
	return nil
}

// authorizeICCID loads a profile and enforces tenant ownership. An unknown
// ICCID is reported as such (8.2.1/3.9), distinct from an authorisation
// failure (8.2.1/1.2).
func (h *Handler) authorizeICCID(tenant, rawICCID string) error {
	p, err := h.Profiles.GetByICCID(iccid.Normalize(rawICCID))
	if err != nil {
		return status.CodeICCIDUnknown.Status("unknown ICCID")
	}
	if p.TenantID != tenant {
		return status.CodeInputRefused.Status("ICCID belongs to another tenant")
	}
	return nil
}

// resolveRequester maps the caller identifier to a tenant. An unwired resolver
// maps nothing: the typed nil *service.TenantResolver used to tolerate a nil
// receiver, which an interface value cannot.
func (h *Handler) resolveRequester(requester string) (tenant string, mapped bool) {
	if h.RequesterTenants == nil {
		return "", false
	}
	return h.RequesterTenants.Resolve(requester)
}

// requesterCount reports how many mappings are configured (0 when unwired).
func (h *Handler) requesterCount() int {
	if h.RequesterTenants == nil {
		return 0
	}
	return h.RequesterTenants.Len()
}
