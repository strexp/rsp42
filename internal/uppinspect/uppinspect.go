// Package uppinspect derives the structural, read-only view of a SAIP profile
// package (header, services, GFSTE list, ProfileElements and files) that the
// management API serves, and renders a personalization dry run.
//
// It sits beside internal/saip rather than inside internal/service because it is
// SAIP codec and validation work with a JSON-facing result shape, not
// orchestration: internal/service keeps the download-path logic and the
// management API keeps the HTTP binding.
package uppinspect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"rsp42/internal/hexutil"
	"rsp42/internal/saip"
	"rsp42/internal/saip/personalization"
)

// PEElement is one ProfileElement summary.
type PEElement struct {
	Tag  string `json:"tag"`
	Name string `json:"name,omitempty"`
	Size int    `json:"size"`
}

// PEFile is one file (EF) summary inside a ProfileElement.
type PEFile struct {
	FID      string `json:"fid"`
	PEName   string `json:"pename,omitempty"`
	BodySize int    `json:"bodySize"`
}

// UPPInspection is the structural validation result for an uploaded SAIP
// profile package (G7: `POST /upp/validate`).
type UPPInspection struct {
	SAIPMajor   int         `json:"saipMajor"`
	SAIPMinor   int         `json:"saipMinor"`
	SAIP        string      `json:"saip"`
	SHA256      string      `json:"sha256"`
	Size        int         `json:"size"`
	ProfileType string      `json:"profileType,omitempty"`
	ICCID       string      `json:"iccid,omitempty"`
	Services    []string    `json:"services"`
	GFSTE       []string    `json:"gfste"`
	Elements    []PEElement `json:"elements"`
	Files       []PEFile    `json:"files"`
	// Warnings lists non-fatal inconsistencies (e.g. a GFSTE entry with no
	// matching ProfileElement present in the package) and baseline advisories.
	Warnings []string `json:"warnings"`
	// Errors lists hard SAIP V2.3.1 constraint violations (N13). A package with
	// errors is not a valid V2.3.1 profile and is refused by POST /upp.
	Errors []string `json:"errors,omitempty"`
}

// InspectUPP parses a UPP binary and returns its structure plus best-effort
// consistency warnings. It never writes to the registry.
func InspectUPP(raw []byte) (*UPPInspection, error) {
	seq, err := saip.ParseUPP(raw)
	if err != nil {
		return nil, err
	}
	hdr, err := saip.ParseHeader(seq.Header())
	if err != nil {
		return nil, fmt.Errorf("profile header: %w", err)
	}
	sum := sha256.Sum256(raw)
	out := &UPPInspection{
		SAIPMajor: int(hdr.Major), SAIPMinor: int(hdr.Minor),
		SAIP:        fmt.Sprintf("%d.%d", hdr.Major, hdr.Minor),
		SHA256:      hex.EncodeToString(sum[:]),
		Size:        len(raw),
		ProfileType: hdr.ProfileType,
		ICCID:       strings.TrimRight(hexutil.Upper(hdr.ICCID), "F"),
		Services:    hdr.Services(),
		GFSTE:       hdr.GFSTEList(),
		Warnings:    []string{},
	}
	if out.Services == nil {
		out.Services = []string{}
	}
	if out.GFSTE == nil {
		out.GFSTE = []string{}
	}
	present := map[string]bool{}
	for _, e := range seq.Elements {
		tag := hexutil.Upper(e.Tag)
		present[saip.PEName(e.Tag)] = true
		out.Elements = append(out.Elements, PEElement{Tag: tag, Name: saip.PEName(e.Tag), Size: len(e.Encode())})
	}
	for _, f := range seq.Files() {
		out.Files = append(out.Files, PEFile{
			FID:    fmt.Sprintf("%04X", f.FID),
			PEName: saip.PEName(f.PE.Tag), BodySize: len(f.Body()),
		})
	}
	// Best-effort consistency: GFSTE entries should resolve to a known
	// ProfileElement name.
	for _, g := range out.GFSTE {
		if g == "" || g == "unknown" {
			continue
		}
		if !present[g] {
			out.Warnings = append(out.Warnings, "GFSTE entry "+g+" has no matching ProfileElement in the package")
		}
	}
	// N13: SAIP V2.3.1 structural and semantic constraints.
	if cv := seq.ValidateV231(); cv != nil {
		out.Errors = cv.Errors
		out.Warnings = append(out.Warnings, cv.Warnings...)
	}
	return out, nil
}

// RenderUPP parses a template, applies the caller-supplied personalization and
// re-encodes it, returning the resulting package's structure and digest. It
// allocates nothing and writes nothing.
func RenderUPP(raw []byte, data *personalization.Data, engine *personalization.Engine) (*UPPInspection, []byte, error) {
	seq, err := saip.ParseUPP(raw)
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		data = &personalization.Data{}
	}
	eng := engine
	if eng == nil {
		eng = &personalization.Engine{}
	}
	if err := eng.Apply(seq, data); err != nil {
		return nil, nil, err
	}
	encoded := seq.Encode()
	ins, err := InspectUPP(encoded)
	if err != nil {
		return nil, nil, err
	}
	return ins, encoded, nil
}
