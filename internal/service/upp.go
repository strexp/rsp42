package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rsp42/internal/saip"
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

// ImportUPPTemplates reads UPP templates (*.der, excluding *UNIQUE*) from dir,
// parses their SAIP version and upserts them into the registry. It is the only
// path that reads UPP files; runtime downloads resolve templates from the
// registry (which also makes them hot-updatable through the admin API/CLI).
//
// The policy is the same profiles.allowed_saip_versions limit the management
// API applies (N16); a nil policy means "no limit". The importer refuses the
// whole run rather than silently skipping, so an over-version template cannot
// enter the registry through the CLI.
func ImportUPPTemplates(dir string, repo *store.UPPRepo, policy *SAIPVersionPolicy) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("upp import: read dir: %w", err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".der") || strings.Contains(name, "UNIQUE") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return n, fmt.Errorf("upp import: %s: %w", name, err)
		}
		major, minor, err := UPPVersion(raw)
		if err != nil {
			return n, fmt.Errorf("upp import: %s: %w", name, err)
		}
		if rej := policy.CheckSAIPVersion(major, minor); rej != nil {
			return n, fmt.Errorf("upp import: %s: %w", name, rej)
		}
		sum := sha256.Sum256(raw)
		if err := repo.Upsert(&store.UPPTemplate{
			Name:      name,
			SAIPMajor: major,
			SAIPMinor: minor,
			SHA256:    hex.EncodeToString(sum[:]),
			Bytes:     raw,
			Active:    true,
		}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// UPPVersion returns the SAIP major/minor declared by an encoded UPP profile.
func UPPVersion(raw []byte) (int, int, error) {
	seq, err := saip.ParseUPP(raw)
	if err != nil {
		return 0, 0, err
	}
	h, err := saip.ParseHeader(seq.Header())
	if err != nil {
		return 0, 0, err
	}
	return int(h.Major), int(h.Minor), nil
}
