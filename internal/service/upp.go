package service

import (
	"rsp42/internal/saipver"
	"rsp42/internal/store"
)

// UPPStore resolves SAIP profile-package templates. The SM-DP+ reads templates
// only from the registry; it never touches the filesystem at request time.
type UPPStore interface {
	// GetForTenant resolves a template for a tenant (own scope first, then the
	// platform-global scope).
	GetForTenant(tenant, name string) (*store.UPPTemplate, error)
	// SelectBestFor returns the best active template for the eUICC's advertised
	// SAIP version set within the tenant's visible scope (N11: the set, not a
	// single version, so a future dual-major rule needs no signature change).
	SelectBestFor(tenant string, versions []saipver.Version) (*store.UPPTemplate, error)
}
