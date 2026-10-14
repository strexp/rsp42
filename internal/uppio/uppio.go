// Package uppio imports SAIP profile-package templates from a directory into the
// registry.
//
// It exists so the filesystem ingestion — the only code path that reads UPP
// files — stays out of internal/service: the SM-DP+ resolves templates from the
// registry at request time and never touches the disk (docs/architecture.md).
package uppio

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rsp42/internal/saip"
	"rsp42/internal/store"
)

// Writer is the registry write path the importer needs. It is defined by the
// consumer so the concrete SQLite repository stays a detail.
type Writer interface {
	Upsert(t *store.UPPTemplate) error
}

// CheckVersion reports whether a SAIP (major, minor) may enter the registry; a
// nil checker means "no limit". The caller supplies the policy so this package
// does not depend on the service layer.
type CheckVersion func(major, minor int) error

// Import reads UPP templates (*.der, excluding *UNIQUE*) from dir, parses their
// SAIP version and upserts them into the registry.
//
// It refuses the whole run rather than silently skipping a rejected template, so
// an over-version template cannot enter the registry through this path (N16).
func Import(dir string, repo Writer, check CheckVersion) (int, error) {
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
		major, minor, err := Version(raw)
		if err != nil {
			return n, fmt.Errorf("upp import: %s: %w", name, err)
		}
		if check != nil {
			if err := check(major, minor); err != nil {
				return n, fmt.Errorf("upp import: %s: %w", name, err)
			}
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

// Version returns the SAIP major/minor declared by an encoded UPP profile.
func Version(raw []byte) (int, int, error) {
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
