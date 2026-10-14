package saip

import "strings"

// SpecificationVersionOID is the SAIP V2.3.1 specification-version OID
// (Annex B: 2.23.143.1.1.2). It is a profile-level tag, not a file-system
// template.
const SpecificationVersionOID = "2.23.143.1.1.2"

// TemplateOIDArc is the arc every file-system template OID lives under
// (Annex B: euicc-profile(1) template(2)).
const TemplateOIDArc = "2.23.143.1.2"

// Template is one SAIP file-system template from Annex B.
type Template struct {
	OID  string
	PE   string // PE name as reported by PEName (e.g. "df-5gs")
	Name string
}

// V231Templates is the complete V2.3.1 file-system template table. Annex B of
// the V2.3.1 specification assigns exactly these 14 OIDs; V2.3.1 has no
// versioned template subarcs (those appear from V3.x, e.g. 2.23.143.1.2.13.2).
//
// The set of template-capable PEs is the templatePE attribute of peDescriptors
// (element.go); this table remains separate because it is keyed by Annex B OID
// and only covers the V2.3.1 baseline subset: the post-V2.3.1 templates
// (df-snpn, iot, opt-iot) are template PEs without a V2.3.1 OID.
//
// Source: "Profile interoperability technical specification V2.3.1", Annex B
// (refs/Profile interoperability technical specification_V2.3.1 Final.pdf).
var V231Templates = []Template{
	{"2.23.143.1.2.1", "mf", "MF system template"},
	{"2.23.143.1.2.2", "cd", "DF CD file system template"},
	{"2.23.143.1.2.3", "telecom", "DF TELECOM file system template"},
	{"2.23.143.1.2.4", "usim", `ADF USIM "created by default" file system template`},
	{"2.23.143.1.2.5", "opt-usim", `ADF USIM "not created by default" file system template`},
	{"2.23.143.1.2.6", "phonebook", "DF PHONEBOOK under ADF USIM file system template"},
	{"2.23.143.1.2.7", "gsm-access", "DF GSM-ACCESS under ADF USIM file system template"},
	{"2.23.143.1.2.8", "isim", `ADF ISIM "created by default" file system template`},
	{"2.23.143.1.2.9", "opt-isim", `ADF ISIM "not created by default" file system template`},
	{"2.23.143.1.2.10", "csim", `ADF CSIM "created by default" file system template`},
	{"2.23.143.1.2.11", "opt-csim", `ADF CSIM "not created by default" file system template`},
	{"2.23.143.1.2.12", "eap", "DF EAP file system template"},
	{"2.23.143.1.2.13", "df-5gs", "DF 5GS file system template"},
	{"2.23.143.1.2.14", "df-saip", "DF SAIP file system template"},
}

var templateByOID = func() map[string]Template {
	m := make(map[string]Template, len(V231Templates))
	for _, t := range V231Templates {
		m[t.OID] = t
	}
	return m
}()

// IsTemplateOID reports whether oid is one of the V2.3.1 file-system templates.
func IsTemplateOID(oid string) bool {
	_, ok := templateByOID[oid]
	return ok
}

// IsTemplateSubarc reports whether oid sits under the template arc without
// being one of the V2.3.1 templates itself, e.g. a versioned child such as
// 2.23.143.1.2.13.2 or an OID from a newer specification.
func IsTemplateSubarc(oid string) bool {
	if !strings.HasPrefix(oid, TemplateOIDArc+".") {
		return false
	}
	return !IsTemplateOID(oid)
}
