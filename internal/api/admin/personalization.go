package admin

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"rsp42/internal/saip/personalization"
)

type persoView struct {
	ICCID          string `json:"iccid"`
	IMSI           string `json:"imsi,omitempty"`
	SPN            string `json:"spn,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`
	HasK           bool   `json:"hasK"`
	HasOPc         bool   `json:"hasOPc"`
	PIN1           string `json:"pin1,omitempty"`
	PUK1           string `json:"puk1,omitempty"`
	ADM1           string `json:"adm1,omitempty"`
	ADM2           string `json:"adm2,omitempty"`
	NumberOfKeccak *int64 `json:"numberOfKeccak,omitempty"`
	// Secrets are only included when explicitly requested (?reveal=1).
	K        string `json:"k,omitempty"`
	OPc      string `json:"opc,omitempty"`
	Rotation string `json:"rotation,omitempty"`
	Xoring   string `json:"xoring,omitempty"`
}

func toPersoView(d *personalization.Data, reveal bool) persoView {
	v := persoView{
		ICCID: d.ICCID, IMSI: d.IMSI, SPN: d.SPN, Algorithm: d.Algorithm,
		HasK: len(d.K) > 0, HasOPc: len(d.OPc) > 0,
		PIN1: d.PIN1, PUK1: d.PUK1, ADM1: d.ADM1, ADM2: d.ADM2, NumberOfKeccak: d.NumberOfKeccak,
	}
	if reveal {
		v.K = strings.ToUpper(hex.EncodeToString(d.K))
		v.OPc = strings.ToUpper(hex.EncodeToString(d.OPc))
		v.Rotation = strings.ToUpper(hex.EncodeToString(d.RotationConstants))
		v.Xoring = strings.ToUpper(hex.EncodeToString(d.XoringConstants))
	}
	return v
}

func (h *Handler) listPerso(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	size := atoiDefault(q.Get("size"), defaultPageSize)
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}
	page := atoiDefault(q.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	reveal := q.Get("reveal") == "1"
	items, total, err := h.Perso.ListPage(q.Get("iccid"), size, (page-1)*size)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]persoView, 0, len(items))
	for _, d := range items {
		views = append(views, toPersoView(d, reveal))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": views, "page": page, "size": size, "total": total})
}

func (h *Handler) getPerso(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	d, err := h.Perso.Resolve(iccid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if d == nil {
		writeErr(w, http.StatusNotFound, "no personalization for ICCID")
		return
	}
	writeJSON(w, http.StatusOK, toPersoView(d, r.URL.Query().Get("reveal") == "1"))
}

type persoReq struct {
	IMSI           string `json:"imsi"`
	K              string `json:"k"`   // hex
	OPc            string `json:"opc"` // hex
	PIN1           string `json:"pin1"`
	PUK1           string `json:"puk1"`
	ADM1           string `json:"adm1"`
	ADM2           string `json:"adm2"`
	SPN            string `json:"spn"`
	Algorithm      string `json:"algorithm"`
	Rotation       string `json:"rotation"` // hex
	Xoring         string `json:"xoring"`   // hex
	NumberOfKeccak *int64 `json:"numberOfKeccak"`
}

func (req *persoReq) toData(iccid string) (*personalization.Data, error) {
	d := &personalization.Data{
		ICCID: iccid, IMSI: req.IMSI, PIN1: req.PIN1, PUK1: req.PUK1,
		ADM1: req.ADM1, ADM2: req.ADM2, SPN: req.SPN, Algorithm: req.Algorithm,
		NumberOfKeccak: req.NumberOfKeccak,
	}
	var err error
	if d.K, err = hexField(req.K, "k"); err != nil {
		return nil, err
	}
	if d.OPc, err = hexField(req.OPc, "opc"); err != nil {
		return nil, err
	}
	if d.RotationConstants, err = hexField(req.Rotation, "rotation"); err != nil {
		return nil, err
	}
	if d.XoringConstants, err = hexField(req.Xoring, "xoring"); err != nil {
		return nil, err
	}
	return d, nil
}

func hexField(s, name string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", name, err)
	}
	return b, nil
}

func (h *Handler) putPerso(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	if iccid == "" {
		writeErr(w, http.StatusBadRequest, "iccid is required")
		return
	}
	var req persoReq
	if !readJSON(w, r, &req) {
		return
	}
	d, err := req.toData(iccid)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.Perso.Put(d); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, "putPersonalization", iccid, "Executed-Success", nil)
	stored, _ := h.Perso.Resolve(iccid)
	writeJSON(w, http.StatusOK, toPersoView(stored, false))
}

func (h *Handler) deletePerso(w http.ResponseWriter, r *http.Request) {
	iccid := normalizeICCID(chi.URLParam(r, "iccid"))
	if err := h.Perso.Delete(iccid); err != nil {
		writeErr(w, http.StatusNotFound, "no personalization for ICCID")
		return
	}
	h.audit(r, "deletePersonalization", iccid, "Executed-Success", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) importPerso(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Records []struct {
			ICCID string `json:"iccid"`
			persoReq
		} `json:"records"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	n := 0
	for i, rec := range req.Records {
		iccid := normalizeICCID(rec.ICCID)
		if iccid == "" {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("record %d has no iccid", i+1))
			return
		}
		d, err := rec.persoReq.toData(iccid)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("record %d: %v", i+1, err))
			return
		}
		if err := h.Perso.Put(d); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		n++
	}
	h.audit(r, "importPersonalization", "", "Executed-Success", map[string]any{"records": n})
	writeJSON(w, http.StatusOK, map[string]any{"imported": n})
}
