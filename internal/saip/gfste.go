package saip

import (
	"bytes"
	"fmt"
	"sort"

	"rsp42/internal/asn1"
)

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

func PEName(tag []byte) string {
	if d := lookupPE(tag); d != nil {
		return d.name
	}
	return ""
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
