package saip

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"rsp42/internal/asn1"
)

// Validation is the outcome of the SAIP V2.3.1 constraint checks (N13).
//
// Errors are hard violations: a template carrying them is not a valid V2.3.1
// profile and the management API refuses to register it. Warnings flag
// constructs that are legal but outside the V2.3.1 baseline (e.g. a mandated
// V3.x-only ProfileElement).
type Validation struct {
	Errors   []string
	Warnings []string
}

// singletonPEs may appear at most once (SAIP V2.3.1 §9; pySim
// validation.py CheckBasicStructure.check_number_of_occurrence).
var singletonPEs = map[string]bool{
	"header": true, "mf": true, "end": true, "cd": true, "telecom": true,
	"usim": true, "isim": true, "csim": true,
	"opt-usim": true, "opt-isim": true, "opt-csim": true,
	"df-saip": true, "df-5gs": true,
}

// optionalPEOrdering lists "optional PE must follow its mandatory base PE"
// dependencies (pySim validation.py check_optional_ordering).
var optionalPEOrdering = [][2]string{
	{"opt-usim", "usim"},
	{"opt-isim", "isim"},
	{"gsm-access", "usim"},
	{"phonebook", "usim"},
	{"df-5gs", "usim"},
	{"df-saip", "usim"},
	{"opt-csim", "csim"},
}

// nonBaselinePEs are ProfileElements introduced after V2.3.1. They parse
// transparently but must not be mandated in a V2.3.1 template (§0.4).
var nonBaselinePEs = map[string]string{
	"be":   "df-snpn",
	"bf20": "iot",
	"bf21": "opt-iot",
	"bf1f": "df-5gprose",
	"bf22": "ssim",
}

// ValidateV231 checks a decoded profile against the SAIP V2.3.1 structural and
// semantic constraints. It never mutates the profile.
func (s *Sequence) ValidateV231() *Validation {
	v := &Validation{}
	errf := func(format string, args ...any) { v.Errors = append(v.Errors, fmt.Sprintf(format, args...)) }
	warnf := func(format string, args ...any) { v.Warnings = append(v.Warnings, fmt.Sprintf(format, args...)) }

	names := make([]string, 0, len(s.Elements))
	counts := map[string]int{}
	index := map[string]int{}
	for i, e := range s.Elements {
		n := PEName(e.Tag)
		names = append(names, n)
		counts[n]++
		if _, ok := index[n]; !ok {
			index[n] = i
		}
	}

	// --- basic structure ---------------------------------------------------
	if len(s.Elements) < 3 {
		errf("profile has %d profile elements; at least header, mf and end are required", len(s.Elements))
	} else {
		if names[0] != "header" {
			errf("first profile element is %s, expected header", peLabel(names[0]))
		}
		if names[1] != "mf" {
			errf("second profile element is %s, expected mf", peLabel(names[1]))
		}
		if names[len(names)-1] != "end" {
			errf("last profile element is %s, expected end", peLabel(names[len(names)-1]))
		}
	}
	for name := range singletonPEs {
		if counts[name] > 1 {
			errf("profile element %s appears %d times, at most once is allowed", name, counts[name])
		}
	}

	// --- optional PE ordering ---------------------------------------------
	for _, dep := range optionalPEOrdering {
		opt, base := dep[0], dep[1]
		if counts[opt] == 0 {
			continue
		}
		if counts[base] == 0 {
			errf("profile element %s is present without %s", opt, base)
			continue
		}
		if index[opt] < index[base] {
			errf("profile element %s must follow %s", opt, base)
		}
	}

	hdr, err := ParseHeader(s.Header())
	if err != nil {
		errf("profile header: %v", err)
		return v
	}

	// --- mandatory services vs PEs ----------------------------------------
	svc := map[string]bool{}
	for _, name := range hdr.Services() {
		svc[name] = true
	}
	requirePE := func(service, pe string) {
		if svc[service] && counts[pe] == 0 {
			errf("mandatory service %s is set but no PE-%s is present", service, strings.ToUpper(pe))
		}
	}
	requirePE("usim", "usim")
	requirePE("isim", "isim")
	requirePE("csim", "csim")
	requireService := func(service, base string) {
		if svc[service] && !svc[base] {
			errf("mandatory service %s requires service %s", service, base)
		}
	}
	requireService("gba-usim", "usim")
	requireService("gba-isim", "isim")
	requireService("multiple-usim", "usim")
	requireService("multiple-isim", "isim")
	requireService("multiple-csim", "csim")
	for _, s := range []string{"get-identity", "profile-a-x25519", "profile-b-p256"} {
		if svc[s] && !svc["usim"] && !svc["isim"] {
			errf("mandatory service %s requires service usim or isim", s)
		}
	}

	// --- mandatory services vs the AKA parameters --------------------------
	type akaInfo struct {
		algo   int
		keyLen int
	}
	var akas []akaInfo
	for _, pe := range s.FindAll(TagAKAParameter) {
		akas = append(akas, akaInfo{algo: AKAAlgorithmID(pe), keyLen: AKAKeyLength(pe)})
	}
	hasAlgo := func(algo int) bool {
		for _, a := range akas {
			if a.algo == algo {
				return true
			}
		}
		return false
	}
	hasAlgoKey := func(algo, keyLen int) bool {
		for _, a := range akas {
			if a.algo == algo && a.keyLen == keyLen {
				return true
			}
		}
		return false
	}
	if svc["milenage"] && !hasAlgo(1) {
		errf("mandatory service milenage is set but no PE-AKAParameter with algorithmID 1 is present")
	}
	if svc["tuak128"] && !hasAlgoKey(2, 16) {
		errf("mandatory service tuak128 is set but no PE-AKAParameter with algorithmID 2 and a 16-byte key is present")
	}
	if svc["tuak256"] && !hasAlgoKey(2, 32) {
		errf("mandatory service tuak256 is set but no PE-AKAParameter with algorithmID 2 and a 32-byte key is present")
	}
	if svc["usim-test-algorithm"] && !hasAlgo(3) {
		errf("mandatory service usim-test-algorithm is set but no PE-AKAParameter with algorithmID 3 is present")
	}
	if svc["cave"] && counts["cdmaParameter"] == 0 {
		errf("mandatory service cave is set but no PE-CDMAParameter is present")
	}

	// --- PE identification uniqueness --------------------------------------
	seenID := map[string]string{}
	for _, e := range s.Elements {
		id, ok := peIdentification(e)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%x", id)
		if prev, dup := seenID[key]; dup {
			errf("PE identification %s is used by both %s and %s", key, prev, peLabel(PEName(e.Tag)))
		} else {
			seenID[key] = peLabel(PEName(e.Tag))
		}
	}

	// --- files -------------------------------------------------------------
	// A File member of a file-bearing PE carries the File CHOICE alternatives
	// directly (fileDescriptor, doNotCreate, fillFileOffset, fillFileContent).
	// The PEHeader ([0]) and templateID ([1]) members are not files.
	for _, e := range s.Elements {
		if !isFileBearing(e.Tag) {
			continue
		}
		pe := PEName(e.Tag)
		n := 0
		for _, field := range e.Children {
			if !isFileField(field) {
				continue
			}
			validateFileEntry(v, pe, n, field)
			n++
		}
	}

	// --- eUICC-Mandatory-GFSTEList ----------------------------------------
	for _, oid := range hdr.GFSTEList() {
		if IsTemplateOID(oid) {
			continue
		}
		if IsTemplateSubarc(oid) {
			errf("GFSTE entry %s is not a V2.3.1 template (versioned or newer-specification subarc)", oid)
			continue
		}
		errf("GFSTE entry %s is not a V2.3.1 file-system template", oid)
	}

	// --- non-baseline PEs --------------------------------------------------
	for _, e := range s.Elements {
		name, known := nonBaselinePEs[hex.EncodeToString(e.Tag)]
		if !known {
			continue
		}
		if h := e.Find(peHeader); h != nil && h.Find(peMandated) != nil {
			warnf("PE-%s (%s) is outside the SAIP V2.3.1 baseline but is marked mandated", strings.ToUpper(name), name)
		}
	}
	return v
}

// validateFileEntry applies the File CHOICE constraints of SAIP V2.3.1 §8.3.3
// (pySim validation.py FileCheckBasicStructure).
func validateFileEntry(v *Validation, pe string, idx int, entry *asn1.Node) {
	errf := func(format string, args ...any) {
		v.Errors = append(v.Errors, fmt.Sprintf("PE-%s file[%d]: %s", strings.ToUpper(pe), idx, fmt.Sprintf(format, args...)))
	}
	descIdx, descCount, hasDoNotCreate := -1, 0, false
	for i, c := range entry.Children {
		switch {
		case bytes.Equal(c.Tag, tagDoNotCreate):
			hasDoNotCreate = true
		case bytes.Equal(c.Tag, tagFcp):
			descCount++
			if descIdx < 0 {
				descIdx = i
			}
		}
	}
	if hasDoNotCreate && len(entry.Children) != 1 {
		errf("doNotCreate must be the only element")
	}
	if descCount > 1 {
		errf("fileDescriptor must appear at most once")
	}
	if descCount == 1 && descIdx != 0 {
		errf("fileDescriptor must be the first element")
	}
}

// peIdentification returns the PEHeader identification number of a profile
// element, when it carries a PEHeader.
func peIdentification(e *asn1.Node) ([]byte, bool) {
	h := e.Find(peHeader)
	if h == nil {
		return nil, false
	}
	id := h.Find(tagInteger)
	if id == nil {
		return nil, false
	}
	return id.Value, true
}

// tagInteger is the universal INTEGER tag of PEHeader.identification.
var tagInteger = []byte{0x02}

// tagDoNotCreate is the File CHOICE alternative [0] (NULL).
var tagDoNotCreate = []byte{0x80}

// tagFileSequence is the universal SEQUENCE tag used when a File is built by
// hand in tests.
var tagFileSequence = []byte{0x30}

// isFileField reports whether a member of a file-bearing PE is a File: it
// carries a fileDescriptor, or it is a bare doNotCreate.
func isFileField(n *asn1.Node) bool {
	if n.Find(tagFcp) != nil {
		return true
	}
	return len(n.Children) == 1 && bytes.Equal(n.Children[0].Tag, tagDoNotCreate)
}

// peLabel renders a PE name for an error message.
func peLabel(name string) string {
	if name == "" {
		return "unknown"
	}
	return name
}
