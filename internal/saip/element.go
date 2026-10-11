package saip

import (
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

// fileBearingTags is the set of PEs that create files.
var fileBearingTags = [][]byte{
	TagGenericFileMgmt, TagMF, TagCD, TagTelecom, TagUSIM, TagOptUSIM, TagISIM, TagOptISIM,
	TagPhonebook, TagGSMAccess, TagCSIM, TagOptCSIM, TagEAP, TagDF5GS, TagDFSAIP, TagDFSNPN,
	TagIoT, TagOptIoT,
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
		if bytesEq(e.Tag, tag) {
			return e
		}
	}
	return nil
}

// FindAll returns every PE with the given tag.
func (s *Sequence) FindAll(tag []byte) []*asn1.Node {
	var out []*asn1.Node
	for _, e := range s.Elements {
		if bytesEq(e.Tag, tag) {
			out = append(out, e)
		}
	}
	return out
}

// Header returns the ProfileHeader PE.
func (s *Sequence) Header() *asn1.Node { return s.Find(TagHeader) }

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isFileBearing(tag []byte) bool {
	for _, t := range fileBearingTags {
		if bytesEq(t, tag) {
			return true
		}
	}
	return false
}
