package saip

import (
	"bytes"
	"fmt"

	"rsp42/internal/asn1"
)

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
