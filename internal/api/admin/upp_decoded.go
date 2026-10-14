package admin

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/saip"
)

type peInfo struct {
	Tag  string `json:"tag"`
	Name string `json:"name,omitempty"`
	Size int    `json:"size"`
}

type fileInfo struct {
	FID      string `json:"fid"`
	PEName   string `json:"peName,omitempty"`
	BodySize int    `json:"bodySize"`
}

type decodedUPP struct {
	Name        string     `json:"name"`
	Major       int        `json:"major"`
	Minor       int        `json:"minor"`
	ProfileType string     `json:"profileType,omitempty"`
	ICCID       string     `json:"iccid,omitempty"`
	Services    []string   `json:"services"`
	GFSTE       []string   `json:"gfste"`
	Elements    []peInfo   `json:"elements"`
	Files       []fileInfo `json:"files"`
}

// decoded returns a read-only structural view of a UPP template (header,
// services, GFSTE list, ProfileElements and files) for external editors.
func (h *Handler) decodedUPP(w http.ResponseWriter, r *http.Request) {
	t, err := h.UPP.GetScoped(scopeTenantParam(r), chi.URLParam(r, "name"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown template")
		return
	}
	seq, err := saip.ParseUPP(t.Bytes)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid UPP: "+err.Error())
		return
	}
	hdr, err := saip.ParseHeader(seq.Header())
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid profile header: "+err.Error())
		return
	}
	out := decodedUPP{
		Name: t.Name, Major: int(hdr.Major), Minor: int(hdr.Minor),
		ProfileType: hdr.ProfileType,
		ICCID:       strings.TrimRight(strings.ToUpper(hex.EncodeToString(hdr.ICCID)), "F"),
		Services:    hdr.Services(),
		GFSTE:       hdr.GFSTEList(),
	}
	if out.Services == nil {
		out.Services = []string{}
	}
	if out.GFSTE == nil {
		out.GFSTE = []string{}
	}
	for _, e := range seq.Elements {
		out.Elements = append(out.Elements, peInfo{
			Tag: strings.ToUpper(hex.EncodeToString(e.Tag)), Name: saip.PEName(e.Tag), Size: len(e.Encode()),
		})
	}
	for _, f := range seq.Files() {
		out.Files = append(out.Files, fileInfo{
			FID:    fmt.Sprintf("%04X", f.FID),
			PEName: saip.PEName(f.PE.Tag), BodySize: len(f.Body()),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
