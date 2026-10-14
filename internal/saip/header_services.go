package saip

import (
	"bytes"

	"rsp42/internal/asn1"
)

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

// RebuildMandatoryGFSTEList recomputes the ProfileHeader's
// eUICC-Mandatory-GFSTEList from the template PEs whose PEHeader carries the
// 'mandated' attribute (SAIP PE_Definitions; cf. pySim
// rebuild_mandatory_gfstelist). OIDs are de-duplicated and sorted.

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
