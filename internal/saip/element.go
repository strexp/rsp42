package saip

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// ProfileElement tags (SAIP PE_Definitions, AUTOMATIC TAGS CHOICE).
var (
	TagHeader          = []byte{0xa0}
	TagGenericFileMgmt = []byte{0xa1}
	TagPinCodes        = []byte{0xa2}
	TagPukCodes        = []byte{0xa3}
	TagAKAParameter    = []byte{0xa4}
	TagCDMAParameter   = []byte{0xa5}
	TagSecurityDomain  = []byte{0xa6}
	TagRFM             = []byte{0xa7}
	TagApplication     = []byte{0xa8}
	TagNonStandard     = []byte{0xa9}
	TagEnd             = []byte{0xaa}
	TagMF              = []byte{0xb0}
	TagCD              = []byte{0xb1}
	TagTelecom         = []byte{0xb2}
	TagUSIM            = []byte{0xb3}
	TagOptUSIM         = []byte{0xb4}
	TagISIM            = []byte{0xb5}
	TagOptISIM         = []byte{0xb6}
	TagPhonebook       = []byte{0xb7}
	TagGSMAccess       = []byte{0xb8}
	TagCSIM            = []byte{0xb9}
	TagOptCSIM         = []byte{0xba}
	TagEAP             = []byte{0xbb}
	TagDF5GS           = []byte{0xbc}
	TagDFSAIP          = []byte{0xbd}
	TagDFSNPN          = []byte{0xbe}
	TagIoT             = []byte{0xbf, 0x20}
	TagOptIoT          = []byte{0xbf, 0x21}
)

// peDescriptor describes one SAIP ProfileElement (PE) in a single place.
//
// Source: "Profile interoperability technical specification V2.3.1",
// PE_Definitions (AUTOMATIC TAGS CHOICE) and §9 (occurrence constraints);
// pySim validation.py is used as the cross-check for the validation attributes.
type peDescriptor struct {
	// tag is the PE CHOICE alternative tag (multi-byte for the IoT pair and the
	// two post-V2.3.1 PEs below).
	tag []byte
	// name is the canonical PE name returned by PEName. It is empty for a PE
	// that ValidateV231 must recognise but that the tag registry deliberately
	// does not name (see the post-V2.3.1 entries at the end of peDescriptors).
	name string

	// fileBearing marks the PEs that create files: PE-GenericFileManagement and
	// every file-system template PE.
	fileBearing bool
	// templatePE marks the file-system template PEs that carry a templateID
	// (SAIP PE_Definitions; PE-GenericFileManagement is excluded). They are the
	// eUICC-Mandatory-GFSTEList candidates of RebuildMandatoryGFSTEList.
	templatePE bool

	// singleton marks the PEs that may appear at most once (SAIP V2.3.1 §9;
	// pySim validation.py CheckBasicStructure.check_number_of_occurrence).
	singleton bool
	// nonBaseline is the specification name of a ProfileElement introduced
	// after V2.3.1. Such PEs parse transparently but must not be mandated in a
	// V2.3.1 template (§0.4), so ValidateV231 warns on them. It is empty for
	// the V2.3.1 baseline.
	nonBaseline string
}

// peDescriptors is the single ProfileElement registry: every per-PE table is
// derived from it (PEName, isFileBearing, isTemplatePE, and the ValidateV231
// singleton/non-baseline checks).
//
// The lists that are not per-PE attributes deliberately stay separate:
//   - serviceNames and the Svc* indices describe the ServicesList BIT STRING
//     (header.go), which is indexed by service bit, not by PE;
//   - V231Templates is the Annex B (template OID, description) table
//     (templates.go), keyed by OID and only covering the V2.3.1 baseline;
//   - optionalPEOrdering is a relation between two PEs (validate.go).
var peDescriptors = []peDescriptor{
	{tag: TagHeader, name: "header", singleton: true},
	{tag: TagGenericFileMgmt, name: "genericFileManagement", fileBearing: true},
	{tag: TagPinCodes, name: "pinCodes"},
	{tag: TagPukCodes, name: "pukCodes"},
	{tag: TagAKAParameter, name: "akaParameter"},
	{tag: TagCDMAParameter, name: "cdmaParameter"},
	{tag: TagSecurityDomain, name: "securityDomain"},
	{tag: TagRFM, name: "rfm"},
	{tag: TagApplication, name: "application"},
	{tag: TagNonStandard, name: "nonStandard"},
	{tag: TagEnd, name: "end", singleton: true},
	{tag: TagMF, name: "mf", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagCD, name: "cd", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagTelecom, name: "telecom", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagUSIM, name: "usim", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagOptUSIM, name: "opt-usim", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagISIM, name: "isim", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagOptISIM, name: "opt-isim", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagPhonebook, name: "phonebook", fileBearing: true, templatePE: true},
	{tag: TagGSMAccess, name: "gsm-access", fileBearing: true, templatePE: true},
	{tag: TagCSIM, name: "csim", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagOptCSIM, name: "opt-csim", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagEAP, name: "eap", fileBearing: true, templatePE: true},
	{tag: TagDF5GS, name: "df-5gs", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagDFSAIP, name: "df-saip", fileBearing: true, templatePE: true, singleton: true},
	{tag: TagDFSNPN, name: "df-snpn", fileBearing: true, templatePE: true, nonBaseline: "df-snpn"},
	{tag: TagIoT, name: "iot", fileBearing: true, templatePE: true, nonBaseline: "iot"},
	{tag: TagOptIoT, name: "opt-iot", fileBearing: true, templatePE: true, nonBaseline: "opt-iot"},
	// Post-V2.3.1 PEs with no tag constant: the parser and ValidateV231 know
	// them, but PEName has never named them, so name stays empty.
	{tag: []byte{0xbf, 0x1f}, nonBaseline: "df-5gprose"},
	{tag: []byte{0xbf, 0x22}, nonBaseline: "ssim"},
}

// peByTag indexes peDescriptors by hex-encoded tag.
var peByTag = func() map[string]*peDescriptor {
	m := make(map[string]*peDescriptor, len(peDescriptors))
	for i := range peDescriptors {
		m[hex.EncodeToString(peDescriptors[i].tag)] = &peDescriptors[i]
	}
	return m
}()

// lookupPE returns the descriptor of a PE tag, or nil when the tag is unknown.
func lookupPE(tag []byte) *peDescriptor {
	return peByTag[hex.EncodeToString(tag)]
}

// isFileBearing reports whether the PE with the given tag creates files.
func isFileBearing(tag []byte) bool {
	d := lookupPE(tag)
	return d != nil && d.fileBearing
}

// isTemplatePE reports whether the PE with the given tag carries a templateID.
func isTemplatePE(tag []byte) bool {
	d := lookupPE(tag)
	return d != nil && d.templatePE
}

// Sequence is an ordered list of SAIP ProfileElements. Unknown PEs are kept as
// their parsed TLV tree and re-encoded transparently.
type Sequence struct {
	Elements []*asn1.Node
}

// ParseUPP parses a UPP (a bare concatenation of ProfileElements).
func ParseUPP(der []byte) (*Sequence, error) {
	nodes, err := asn1.ParseNodes(der)
	if err != nil {
		return nil, fmt.Errorf("saip: parse UPP: %w", err)
	}
	return &Sequence{Elements: nodes}, nil
}

// Encode re-serializes the profile element sequence.
func (s *Sequence) Encode() []byte {
	var out []byte
	for _, e := range s.Elements {
		out = append(out, e.Encode()...)
	}
	return out
}

// Find returns the first PE with the given tag.
func (s *Sequence) Find(tag []byte) *asn1.Node {
	for _, e := range s.Elements {
		if bytes.Equal(e.Tag, tag) {
			return e
		}
	}
	return nil
}

// FindAll returns every PE with the given tag.
func (s *Sequence) FindAll(tag []byte) []*asn1.Node {
	var out []*asn1.Node
	for _, e := range s.Elements {
		if bytes.Equal(e.Tag, tag) {
			out = append(out, e)
		}
	}
	return out
}

// Header returns the ProfileHeader PE.
func (s *Sequence) Header() *asn1.Node { return s.Find(TagHeader) }
