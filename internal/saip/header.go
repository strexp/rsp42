package saip

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"

	"rsp42/internal/asn1"
)

// Header field tags (ProfileHeader, AUTOMATIC TAGS).
var (
	hdrMajor       = []byte{0x80}
	hdrMinor       = []byte{0x81}
	hdrProfileType = []byte{0x82}
	hdrICCID       = []byte{0x83}
	hdrServices    = []byte{0xa5}
	hdrGFSTE       = []byte{0xa6}
)

// PE-header field tags (PEHeader, AUTOMATIC TAGS).
var (
	peMandated = []byte{0x80} // mandated NULL
	peTemplate = []byte{0x81} // templateID OID
	peHeader   = []byte{0xa0} // <x>-header PEHeader
	tagOID     = []byte{0x06}
)

// Header is a decoded ProfileHeader.
type Header struct {
	Node        *asn1.Node
	Major       byte
	Minor       byte
	ProfileType string
	ICCID       []byte // 10 raw BCD bytes
}

// ParseHeader decodes the ProfileHeader PE.
func ParseHeader(pe *asn1.Node) (*Header, error) {
	if pe == nil || !bytes.Equal(pe.Tag, TagHeader) {
		return nil, fmt.Errorf("saip: not a ProfileHeader PE")
	}
	h := &Header{Node: pe}
	if n := pe.Find(hdrMajor); n != nil && len(n.Value) > 0 {
		h.Major = n.Value[0]
	}
	if n := pe.Find(hdrMinor); n != nil && len(n.Value) > 0 {
		h.Minor = n.Value[0]
	}
	if n := pe.Find(hdrProfileType); n != nil {
		h.ProfileType = string(n.Value)
	}
	if n := pe.Find(hdrICCID); n != nil {
		h.ICCID = n.Value
	}
	return h, nil
}

// SetICCID replaces (or inserts) the header ICCID.
func (h *Header) SetICCID(iccid []byte) {
	if n := h.Node.Find(hdrICCID); n != nil {
		n.Value = append([]byte(nil), iccid...)
		return
	}
	h.Node.AppendChild(asn1.NewPrimitive(hdrICCID, iccid))
	h.ICCID = iccid
}

// HasService reports whether the mandatory-services list contains the NULL
// with the given automatic index.
func (h *Header) HasService(idx int) bool {
	services := h.Node.Find(hdrServices)
	if services == nil {
		return false
	}
	return services.Find(asn1.Ctx(uint64(idx), false)) != nil
}

// SetService ensures the mandatory-services list contains a NULL for the given
// automatic tag number (services are all-untagged NULLs, tagged [0..]).
func (h *Header) SetService(idx int, present bool) {
	services := h.Node.Find(hdrServices)
	if services == nil {
		if !present {
			return
		}
		services = asn1.NewConstructed(hdrServices)
		h.Node.AppendChild(services)
	}
	tag := asn1.Ctx(uint64(idx), false)
	existing := services.Find(tag)
	if present && existing == nil {
		services.AppendChild(asn1.NewPrimitive(tag, nil))
	} else if !present && existing != nil {
		services.RemoveAll(tag)
	}
}

// Service indices in ServicesList (order of declaration).
//
// Indices 0-18 are the V2.3.1 list; 19-23 are the additions up to V2.3.1
// (dfLink, cat-tp, get-identity, profile-a-x25519, profile-b-p256). The five
// entries introduced by the V3.2 specification (suciCalculatorApi,
// dns-resolution, scp11ac, scp11c-authorization-mechanism, s16mode) are
// deliberately not reserved: SAIP V3.x is out of scope (docs/esim42-integration-gaps.md §0.4).
const (
	SvcContactless = iota
	SvcUSIM
	SvcISIM
	SvcCSIM
	SvcMilenage
	SvcTUAK128
	SvcCave
	SvcGBAUSIM
	SvcGBAISIM
	SvcMBMS
	SvcEAP
	SvcJavaCard
	SvcMultOS
	SvcMultipleUSIM
	SvcMultipleISIM
	SvcMultipleCSIM
	SvcTUAK256
	SvcUSIMTestAlgorithm
	SvcBERTLV
	SvcDFLink
	SvcCATTp
	SvcGetIdentity
	SvcProfileAX25519
	SvcProfileBP256
)

// svcMax is the highest ServicesList index this build understands; it is the
// loop bound of Services().
const svcMax = SvcProfileBP256

// RebuildMandatoryServices derives the mandatory-services list from the PEs
// actually present in the profile (USIM/ISIM/CSIM/EAP presence and the AKA
// algorithm, including the TUAK key length). It is a best-effort recomputation
// and covers the services the ProfileElements can imply.
//
// Responsibility boundary (C11): this function only writes the
// eUICC-Mandatory-services BIT STRING of the ProfileHeader. The
// eUICC-Mandatory-GFSTEList is a separate structure owned exclusively by
// RebuildMandatoryGFSTEList below; neither function touches the other's data.
// Adding a service constant therefore does NOT make it auto-set unless the
// corresponding PE is derived here.
func (s *Sequence) RebuildMandatoryServices() error {
	h, err := ParseHeader(s.Header())
	if err != nil {
		return err
	}
	usim := s.Find(TagUSIM) != nil || s.Find(TagOptUSIM) != nil
	isim := s.Find(TagISIM) != nil || s.Find(TagOptISIM) != nil
	csim := s.Find(TagCSIM) != nil || s.Find(TagOptCSIM) != nil
	eap := s.Find(TagEAP) != nil
	aka := s.Find(TagAKAParameter)
	algo := 0
	if aka != nil {
		algo = AKAAlgorithmID(aka)
	}
	h.SetService(SvcUSIM, usim)
	h.SetService(SvcISIM, isim)
	h.SetService(SvcCSIM, csim)
	h.SetService(SvcEAP, eap)
	h.SetService(SvcMilenage, algo == 1)
	// TUAK is one algorithm id (2) with two key lengths: a 32-byte K selects
	// TUAK-256, everything else TUAK-128 (matching pySim's length-based rule).
	// Without this, SvcTUAK256 was declared but never set.
	h.SetService(SvcTUAK128, algo == 2 && AKAKeyLength(aka) != 32)
	h.SetService(SvcTUAK256, algo == 2 && AKAKeyLength(aka) == 32)
	h.SetService(SvcUSIMTestAlgorithm, algo == 3)
	return nil
}

// templatePETags are the file-system template PEs that carry a templateID
// (SAIP PE_Definitions; PE-GenericFileManagement is excluded).
var templatePETags = [][]byte{
	TagMF, TagCD, TagTelecom, TagUSIM, TagOptUSIM, TagPhonebook, TagGSMAccess,
	TagDF5GS, TagDFSAIP, TagDFSNPN, TagISIM, TagOptISIM, TagCSIM, TagOptCSIM,
	TagEAP, TagIoT, TagOptIoT,
}

func isTemplatePE(tag []byte) bool {
	for _, t := range templatePETags {
		if bytes.Equal(t, tag) {
			return true
		}
	}
	return false
}

// RebuildMandatoryGFSTEList recomputes the ProfileHeader's
// eUICC-Mandatory-GFSTEList from the template PEs whose PEHeader carries the
// 'mandated' attribute (SAIP PE_Definitions; cf. pySim
// rebuild_mandatory_gfstelist). OIDs are de-duplicated and sorted.
func (s *Sequence) RebuildMandatoryGFSTEList() error {
	hd := s.Header()
	if hd == nil {
		return fmt.Errorf("saip: no ProfileHeader PE")
	}
	var oids [][]byte
	for _, pe := range s.Elements {
		if !isTemplatePE(pe.Tag) {
			continue
		}
		h := pe.Find(peHeader)
		if h == nil || h.Find(peMandated) == nil {
			continue
		}
		tid := pe.Find(peTemplate)
		if tid == nil || len(tid.Value) == 0 {
			continue
		}
		oids = append(oids, append([]byte(nil), tid.Value...))
	}
	sort.Slice(oids, func(i, j int) bool { return bytes.Compare(oids[i], oids[j]) < 0 })

	list := asn1.NewConstructed(hdrGFSTE)
	var prev []byte
	for _, oid := range oids {
		if prev != nil && bytes.Equal(prev, oid) {
			continue
		}
		list.AppendChild(asn1.NewPrimitive(tagOID, oid))
		prev = oid
	}

	// Replace the existing GFSTE list in place, preserving field order.
	idx := -1
	kept := make([]*asn1.Node, 0, len(hd.Children))
	for i, c := range hd.Children {
		if bytes.Equal(c.Tag, hdrGFSTE) {
			if idx < 0 {
				idx = i
			}
			continue
		}
		kept = append(kept, c)
	}
	if idx < 0 || idx > len(kept) {
		idx = len(kept)
	}
	kept = append(kept, nil)
	copy(kept[idx+1:], kept[idx:])
	kept[idx] = list
	hd.Children = kept
	return nil
}

// serviceNames maps ServicesList indices to their SGP.22 / SAIP names.
var serviceNames = map[int]string{
	SvcContactless: "contactless", SvcUSIM: "usim", SvcISIM: "isim", SvcCSIM: "csim",
	SvcMilenage: "milenage", SvcTUAK128: "tuak128", SvcCave: "cave",
	SvcGBAUSIM: "gba-usim", SvcGBAISIM: "gba-isim", SvcMBMS: "mbms", SvcEAP: "eap",
	SvcJavaCard: "javacard", SvcMultOS: "multos", SvcMultipleUSIM: "multiple-usim",
	SvcMultipleISIM: "multiple-isim", SvcMultipleCSIM: "multiple-csim", SvcTUAK256: "tuak256",
	SvcUSIMTestAlgorithm: "usim-test-algorithm",
	// SAIP V2.3.1 spells this "ber-tlv"; the previous "bertlv" value was a
	// contract deviation for /upp/{name}/decoded (C7).
	SvcBERTLV:         "ber-tlv",
	SvcDFLink:         "dfLink",
	SvcCATTp:          "cat-tp",
	SvcGetIdentity:    "get-identity",
	SvcProfileAX25519: "profile-a-x25519",
	SvcProfileBP256:   "profile-b-p256",
}

// Services returns the mandatory services advertised by the header.
func (h *Header) Services() []string {
	var out []string
	for i := SvcContactless; i <= svcMax; i++ {
		if h.HasService(i) {
			out = append(out, serviceNames[i])
		}
	}
	return out
}

// GFSTEList returns the eUICC-Mandatory-GFSTEList OIDs as dotted strings.
func (h *Header) GFSTEList() []string {
	node := h.Node.Find(hdrGFSTE)
	if node == nil {
		return nil
	}
	var out []string
	for _, c := range node.Children {
		if bytes.Equal(c.Tag, tagOID) {
			if oid, err := asn1.DecodeOID(c.Value); err == nil {
				out = append(out, oid)
			}
		}
	}
	return out
}

// PEName returns a human-readable name for a ProfileElement tag, or "".
func PEName(tag []byte) string {
	return peNames[hex.EncodeToString(tag)]
}

var peNames = map[string]string{
	"a0": "header", "a1": "genericFileManagement", "a2": "pinCodes", "a3": "pukCodes",
	"a4": "akaParameter", "a5": "cdmaParameter", "a6": "securityDomain", "a7": "rfm",
	"a8": "application", "a9": "nonStandard", "aa": "end",
	"b0": "mf", "b1": "cd", "b2": "telecom", "b3": "usim", "b4": "opt-usim",
	"b5": "isim", "b6": "opt-isim", "b7": "phonebook", "b8": "gsm-access",
	"b9": "csim", "ba": "opt-csim", "bb": "eap", "bc": "df-5gs", "bd": "df-saip",
	"be": "df-snpn", "bf20": "iot", "bf21": "opt-iot",
}

// AKAAlgorithmID navigates PE-AKAParameter → algoConfiguration → algoParameter
// → algorithmID.
func AKAAlgorithmID(pe *asn1.Node) int {
	cfg := pe.Find(asn1.Ctx(1, true)) // algoConfiguration [1]
	if cfg == nil {
		return 0
	}
	algo := cfg.Find(asn1.Ctx(1, true)) // algoParameter [1]
	if algo == nil {
		return 0
	}
	id := algo.Find(asn1.Ctx(0, false)) // algorithmID [0]
	if id == nil || len(id.Value) == 0 {
		return 0
	}
	return int(id.Value[len(id.Value)-1])
}

// AKAKeyLength returns the length in bytes of the K key inside a
// PE-AKAParameter (algoConfiguration → algoParameter → key [2]), or 0 when it is
// absent. It distinguishes TUAK-128 from TUAK-256, which share algorithm id 2.
func AKAKeyLength(pe *asn1.Node) int {
	if pe == nil {
		return 0
	}
	cfg := pe.Find(asn1.Ctx(1, true))
	if cfg == nil {
		return 0
	}
	algo := cfg.Find(asn1.Ctx(1, true))
	if algo == nil {
		return 0
	}
	k := algo.Find(asn1.Ctx(2, false))
	if k == nil {
		return 0
	}
	return len(k.Value)
}
