package admin

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"rsp42/internal/api/adminhttp"
	"rsp42/internal/hexutil"
	"strconv"
	"strings"
	"time"
)

const exportLimit = 100000

func wantCSV(r *http.Request) bool {
	return r.URL.Query().Get("format") != "json"
}

// exportProfiles streams the profile inventory as CSV or JSON.
func (h *Handler) exportProfiles(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := profileFilterFromQuery(q)
	items, _, err := h.Profiles.ListFiltered(filter, exportLimit, 0, q.Get("sort"))
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !wantCSV(r) {
		views := make([]profileView, 0, len(items))
		for _, p := range items {
			views = append(views, toProfileView(p))
		}
		adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=profiles.csv")
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"iccid", "tenant", "externalRef", "imsi", "profileType", "eid", "state", "matchingId", "ccRequired",
		"smdsAddress", "uppTemplate", "pprIds", "downloadAttempts", "ccAttempts", "batchId", "createdAt", "updatedAt", "installedAt", "errorReason"})
	for _, p := range items {
		installed, batch := "", ""
		if p.InstalledAt != nil {
			installed = p.InstalledAt.UTC().Format(time.RFC3339)
		}
		if p.BatchID != nil {
			batch = strconv.FormatInt(*p.BatchID, 10)
		}
		_ = cw.Write([]string{
			p.ICCID, p.TenantID, p.ExternalRef, p.IMSI, p.ProfileType, p.EID, string(p.State), p.MatchingID,
			strconv.FormatBool(p.CCRequired), p.SMDSAddress, p.UPPTemplate, hexutil.Upper(p.PPRIds),
			strconv.Itoa(p.DownloadAttempts), strconv.Itoa(p.CCAttempts), batch,
			p.CreatedAt.UTC().Format(time.RFC3339), p.UpdatedAt.UTC().Format(time.RFC3339),
			installed, p.ErrorReason,
		})
	}
}

// exportPersonalization streams personalization records as CSV or JSON. K/OPc
// are included (this is a data export endpoint).
func (h *Handler) exportPersonalization(w http.ResponseWriter, r *http.Request) {
	tenant := scopeTenantParam(r)
	items, _, err := h.Perso.ListPage(r.URL.Query().Get("iccid"), tenant, exportLimit, 0)
	if err != nil {
		adminhttp.WriteErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !wantCSV(r) {
		views := make([]persoView, 0, len(items))
		for _, d := range items {
			views = append(views, toPersoView(d, true))
		}
		adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"items": views, "total": len(views)})
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=personalization.csv")
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"iccid", "imsi", "k", "opc", "pin1", "puk1", "adm1", "adm2", "spn", "algorithm",
		"rotation", "xoring", "numberOfKeccak", "plmn", "msisdn", "acc", "filePatches"})
	for _, d := range items {
		keccak, acc, plmn, patches := "", "", "", ""
		if d.NumberOfKeccak != nil {
			keccak = strconv.FormatInt(*d.NumberOfKeccak, 10)
		}
		if d.ACC != nil {
			acc = strconv.Itoa(int(*d.ACC))
		}
		if len(d.PLMN) > 0 {
			if b, err := json.Marshal(d.PLMN); err == nil {
				plmn = string(b)
			}
		}
		if len(d.FilePatches) > 0 {
			if b, err := json.Marshal(d.FilePatches); err == nil {
				patches = string(b)
			}
		}
		_ = cw.Write([]string{
			d.ICCID, d.IMSI, hexutil.Upper(d.K), hexutil.Upper(d.OPc), d.PIN1, d.PUK1, d.ADM1, d.ADM2,
			d.SPN, d.Algorithm, hexutil.Upper(d.RotationConstants), hexutil.Upper(d.XoringConstants), keccak,
			plmn, d.MSISDN, acc, patches,
		})
	}
}

type importProfilesReq struct {
	Tenant  string                `json:"tenant"`
	Records []importProfileRecord `json:"records"`
}

// importProfiles creates profiles from a JSON list (round-trips exportProfiles)
// or from a CSV upload (text/csv or ?format=csv).
func (h *Handler) importProfiles(w http.ResponseWriter, r *http.Request) {
	var req importProfilesReq
	if strings.Contains(r.Header.Get("Content-Type"), "text/csv") ||
		(r.Method == http.MethodPost && r.URL.Query().Get("format") == "csv") {
		recs, err := readProfileCSV(r)
		if err != nil {
			adminhttp.WriteErr(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Records = recs
	} else if !adminhttp.ReadJSON(w, r, &req) {
		return
	}
	type result struct {
		ICCID string `json:"iccid"`
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}
	defaultTenant, err := h.effectiveTenant(r, req.Tenant)
	if err != nil {
		writeTenantErr(w, err)
		return
	}
	results := make([]result, 0, len(req.Records))
	ok := 0
	for _, rec := range req.Records {
		recTenant := defaultTenant
		if rec.Tenant != "" {
			if recTenant, err = h.effectiveTenant(r, rec.Tenant); err != nil {
				results = append(results, result{ICCID: rec.ICCID, Error: err.Error()})
				continue
			}
		}
		p, err := h.Inventory.Allocate(serviceAllocate(createProfileReq{
			ICCID: rec.ICCID, EID: rec.EID, ProfileType: rec.ProfileType,
			UPPTemplate: rec.UPPTemplate, ExternalRef: rec.ExternalRef,
		}, recTenant))
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
	adminhttp.WriteJSON(w, http.StatusOK, map[string]any{"imported": ok, "results": results})
}

// importProfileRecord is one row of a profile import (JSON or CSV).
type importProfileRecord struct {
	ICCID       string `json:"iccid"`
	EID         string `json:"eid"`
	ProfileType string `json:"profileType"`
	MatchingID  string `json:"matchingId"`
	SMDSAddress string `json:"smdsAddress"`
	UPPTemplate string `json:"uppTemplate"`
	ExternalRef string `json:"externalRef"`
	Tenant      string `json:"tenant"`
}

// readProfileCSV parses a profile CSV upload. The header row is required;
// unknown columns are ignored and every row is reported individually by the
// caller, so one malformed row never aborts the import.
func readProfileCSV(r *http.Request) ([]importProfileRecord, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	cr := csv.NewReader(bytes.NewReader(body))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty CSV body")
	}
	index := map[string]int{}
	for i, name := range rows[0] {
		index[strings.TrimSpace(strings.ToLower(name))] = i
	}
	if _, ok := index["iccid"]; !ok {
		return nil, fmt.Errorf("CSV header must contain an iccid column")
	}
	out := make([]importProfileRecord, 0, len(rows)-1)
	for _, row := range rows[1:] {
		get := func(name string) string {
			i, ok := index[name]
			if !ok || i >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[i])
		}
		out = append(out, importProfileRecord{
			ICCID: get("iccid"), EID: get("eid"), ProfileType: get("profiletype"),
			MatchingID: get("matchingid"), SMDSAddress: get("smdsaddress"),
			UPPTemplate: get("upptemplate"), ExternalRef: get("externalref"), Tenant: get("tenant"),
		})
	}
	return out, nil
}
