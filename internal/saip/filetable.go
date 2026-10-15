package saip

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
)

// TemplateFile is one file of a SAIP V2.3.1 Annex A file-system template.
//
// Source: "Profile interoperability technical specification V2.3.1",
// Annex A §9.2–§9.8 (refs/Profile interoperability technical specification_V2.3.1
// Final.pdf). The PE→file partition follows the ASN.1 definitions of §8.3.4
// (PE-MF, PE-CD, PE-TELECOM, PE-USIM, PE-OPT-USIM, PE-PHONEBOOK,
// PE-GSM-ACCESS, PE-ISIM, PE-OPT-ISIM, PE-CSIM, PE-OPT-CSIM, PE-EAP,
// PE-DF-5GS, PE-DF-SAIP); only the V2.3.1 baseline templates are covered.
//
// Sentinel values:
//   - NBRec == -1 means the Annex A cell is "X": the parameter has no default
//     and must be provided by the Profile Creator (a "params" entry).
//   - NBRec == 0 means the cell is "NA" (not applicable for this file type).
//   - Size == -1 / 0 have the same meaning for the File/Rec Size column.
//   - FIDEnd is 0 for a single-FID entry; otherwise [FID, FIDEnd] is the
//     Annex A FID range (e.g. EF.ICON 4F80–4FBF).
//   - SFI == 0 means the template defines no default SFI.
//   - ARR is the access-rules reference (record number in the surrounding
//     EF.ARR); 0 means the cell is empty.
type TemplateFile struct {
	FID     uint16
	FIDEnd  uint16
	Name    string
	Type    string // MF, DF, ADF, TR, LF, CY, BT
	NBRec   int
	Size    int
	ARR     int
	SFI     int
	Default string
	// ContentRequired mirrors the Annex A "Content Required" column: "Y" means
	// no default content exists and the Profile Creator must provide it.
	ContentRequired bool
	// Params is the Annex A "Parameters" column, i.e. the parameters the
	// Profile Creator has to provide in addition to the template values.
	Params string
	// AssServ is the Annex A "Ass. Serv." column (the USIM/ISIM service-table
	// association of the file), informational.
	AssServ string
}

// InRange reports whether fid falls inside this template file entry.
func (f TemplateFile) InRange(fid uint16) bool {
	if f.FID == 0 {
		return false
	}
	if f.FIDEnd == 0 {
		return fid == f.FID
	}
	return fid >= f.FID && fid <= f.FIDEnd
}

// requiredParam reports whether the Annex A Parameters column names param
// (case-insensitive substring match; the column uses "Record size, File size"
// and "File size, SFI" style lists).
func (f TemplateFile) requiredParam(param string) bool {
	return strings.Contains(strings.ToLower(f.Params), strings.ToLower(param))
}

// templateFileData is the Annex A table, one record per line, pipe separated:
//
//	pe | fid | fidEnd | name | type | nbrec | size | arr | sfi | default | contentReq | params | assServ
//
// Empty cells are empty fields; "-" means the "X" placeholder (no default, must
// be provided). Lines starting with '#' and blank lines are ignored. The
// ordering inside each template follows the Annex A tables; a DF or ADF entry
// opens the file-system scope the following EF entries belong to (the Annex A
// tables list a DF immediately before the files it contains).
//
//go:embed filetable.txt
var templateFileData string

// templateFiles is the parsed Annex A table keyed by PE name.
var templateFiles = parseTemplateFileData(templateFileData)

func parseTemplateFileData(data string) map[string][]TemplateFile {
	out := map[string][]TemplateFile{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 13 {
			panic(fmt.Sprintf("saip: template file table: expected 13 fields, got %d in %q", len(fields), line))
		}
		f := TemplateFile{
			Name:            fields[3],
			Type:            fields[4],
			NBRec:           parseTemplateInt(fields[5]),
			Size:            parseTemplateInt(fields[6]),
			ARR:             parseIntOr0(fields[7]),
			SFI:             parseHexOr0(fields[8]),
			Default:         fields[9],
			ContentRequired: fields[10] == "Y",
			Params:          fields[11],
			AssServ:         fields[12],
		}
		f.FID = uint16(parseHexOr0(fields[1]))
		if fields[2] != "" {
			f.FIDEnd = uint16(parseHexOr0(fields[2]))
		}
		out[fields[0]] = append(out[fields[0]], f)
	}
	return out
}

func parseTemplateInt(s string) int {
	if s == "-" {
		return -1
	}
	return parseIntOr0(s)
}

func parseIntOr0(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		panic(fmt.Sprintf("saip: template file table: bad integer %q: %v", s, err))
	}
	return n
}

func parseHexOr0(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		panic(fmt.Sprintf("saip: template file table: bad hex %q: %v", s, err))
	}
	return int(n)
}

// TemplateFiles returns the Annex A file list of a template, keyed by the PE
// name used by PEName (e.g. "usim", "opt-usim", "df-5gs"). It returns nil for
// a PE that is not backed by a V2.3.1 file-system template (e.g.
// "genericFileManagement").
func TemplateFiles(pe string) []TemplateFile {
	return templateFiles[pe]
}

// FindTemplateFile looks up a file of a template by FID, honouring FID ranges.
// The first match wins; FIDs are not unique across every template (e.g. 4F20
// is EF.IMG under DF GRAPHICS and EF.MLPL under DF MMSS in the TELECOM
// template), so callers that need the exact file must also consider the
// surrounding DF scope.
func FindTemplateFile(pe string, fid uint16) (TemplateFile, bool) {
	for _, f := range templateFiles[pe] {
		if f.InRange(fid) {
			return f, true
		}
	}
	return TemplateFile{}, false
}

// IsTemplateFileFID reports whether fid is one of the files of the template.
func IsTemplateFileFID(pe string, fid uint16) bool {
	_, ok := FindTemplateFile(pe, fid)
	return ok
}
