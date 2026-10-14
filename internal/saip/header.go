package saip

import (
	"bytes"
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
	if pe == nil || !bytesEq(pe.Tag, TagHeader) {
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
)

// RebuildMandatoryServices derives the mandatory-services list from the PEs
// actually present in the profile. It is a best-effort recomputation (the
// GFSTE list is left untouched).
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
	h.SetService(SvcTUAK128, algo == 2)
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
		if bytesEq(t, tag) {
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
		if bytesEq(c.Tag, hdrGFSTE) {
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
