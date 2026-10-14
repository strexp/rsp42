package admin

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"rsp42/internal/store"
)

const exportLimit = 100000

func wantCSV(r *http.Request) bool {
	return r.URL.Query().Get("format") != "json"
}

// exportProfiles streams the profile inventory as CSV or JSON.
func (h *Handler) exportProfiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := store.ProfileFilter{State: q.Get("state"), EID: q.Get("eid"), ICCID: q.Get("iccid"), Query: q.Get("q")}
	items, _, err := h.Profiles.ListFiltered(filter, exportLimit, 0, q.Get("sort"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !wantCSV(r) {
		views := make([]profileView, 0, len(items))
		for _, p := range items {
			views = append(views, toProfileView(p))
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=profiles.csv")
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"iccid", "imsi", "profileType", "eid", "state", "matchingId", "ccRequired",
		"smdsAddress", "uppTemplate", "pprIds", "downloadAttempts", "ccAttempts", "createdAt", "updatedAt", "installedAt", "errorReason"})
	for _, p := range items {
		installed := ""
		if p.InstalledAt != nil {
			installed = p.InstalledAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			p.ICCID, p.IMSI, p.ProfileType, p.EID, string(p.State), p.MatchingID,
			strconv.FormatBool(p.CCRequired), p.SMDSAddress, p.UPPTemplate, hexUpper(p.PPRIds),
			strconv.Itoa(p.DownloadAttempts), strconv.Itoa(p.CCAttempts),
			p.CreatedAt.UTC().Format(time.RFC3339), p.UpdatedAt.UTC().Format(time.RFC3339),
			installed, p.ErrorReason,
		})
	}
}

// exportPersonalization streams personalization records as CSV or JSON. K/OPc
// are included (this is a data export endpoint).
func (h *Handler) exportPersonalization(w http.ResponseWriter, r *http.Request) {
	items, _, err := h.Perso.ListPage(r.URL.Query().Get("iccid"), exportLimit, 0)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !wantCSV(r) {
		views := make([]persoView, 0, len(items))
		for _, d := range items {
			views = append(views, toPersoView(d, true))
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=personalization.csv")
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"iccid", "imsi", "k", "opc", "pin1", "puk1", "adm1", "adm2", "spn", "algorithm", "rotation", "xoring", "numberOfKeccak"})
	for _, d := range items {
		keccak := ""
		if d.NumberOfKeccak != nil {
			keccak = strconv.FormatInt(*d.NumberOfKeccak, 10)
		}
		_ = cw.Write([]string{
			d.ICCID, d.IMSI, hexUpper(d.K), hexUpper(d.OPc), d.PIN1, d.PUK1, d.ADM1, d.ADM2,
			d.SPN, d.Algorithm, hexUpper(d.RotationConstants), hexUpper(d.XoringConstants), keccak,
		})
	}
}

type importProfilesReq struct {
	Records []struct {
		ICCID       string `json:"iccid"`
		EID         string `json:"eid"`
		ProfileType string `json:"profileType"`
		MatchingID  string `json:"matchingId"`
		SMDSAddress string `json:"smdsAddress"`
	} `json:"records"`
}

// importProfiles creates profiles from a JSON list (round-trips exportProfiles).
func (h *Handler) importProfiles(w http.ResponseWriter, r *http.Request) {
	var req importProfilesReq
	if !readJSON(w, r, &req) {
		return
	}
	type result struct {
		ICCID string `json:"iccid"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(req.Records))
	ok := 0
	for _, rec := range req.Records {
		p, err := h.Inventory.Allocate(rec.EID, rec.ProfileType, rec.ICCID)
		if err == nil {
			if rec.MatchingID != "" || rec.SMDSAddress != "" {
				if rec.MatchingID != "" {
					p.MatchingID = rec.MatchingID
				}
				if rec.SMDSAddress != "" {
					p.SMDSAddress = rec.SMDSAddress
				}
				err = h.Profiles.Update(p)
			}
		}
		res := result{ICCID: rec.ICCID, OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		} else {
			res.ICCID, ok = p.ICCID, ok+1
		}
		results = append(results, res)
	}
	h.audit(r, "importProfiles", "", "Executed-Success", map[string]any{"imported": ok, "total": len(req.Records)})
	writeJSON(w, http.StatusOK, map[string]any{"imported": ok, "results": results})
}

func hexUpper(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const d = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, d[x>>4], d[x&0x0f])
	}
	return string(out)
}
