package service

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

// UPPStore resolves SAIP profile-package templates. The SM-DP+ reads templates
// only from the registry; it never touches the filesystem at request time.
type UPPStore interface {
	GetByName(name string) (*store.UPPTemplate, error)
	SelectBest(major, minor int) (*store.UPPTemplate, error)
	Any() (*store.UPPTemplate, error)
}

// ImportUPPTemplates reads UPP templates (*.der, excluding *UNIQUE*) from dir,
// parses their SAIP version and upserts them into the registry. It is the only
// path that reads UPP files; runtime downloads resolve templates from the
// registry (which also makes them hot-updatable through the admin API/CLI).
func ImportUPPTemplates(dir string, repo *store.UPPRepo) (int, error) {
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
