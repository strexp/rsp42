package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// BoundProfilePackage is the BF36 shell assembled by the SM-DP+ (SGP.22 §5.5).
type BoundProfilePackage struct {
	InitialiseSecureChannelRequest *InitialiseSecureChannelRequest
	FirstSequenceOf87              [][]byte // protected ConfigureISDP segments (BF24)
	SequenceOf88                   [][]byte // protected StoreMetadata segments (BF25)
	SecondSequenceOf87             [][]byte // protected ReplaceSessionKeys segments (BF26), optional
	SequenceOf86                   [][]byte // protected UPP segments
}

// Assemble encodes the BoundProfilePackage to its wire form. It concatenates
// the already-encoded children byte-for-byte so the raw BSP segments and the
// signed BF23 element are preserved exactly.
func (b *BoundProfilePackage) Assemble() []byte {
	var content []byte
	content = append(content, b.InitialiseSecureChannelRequest.Encode()...)
	content = append(content, segmentGroupBytes(0, 7, b.FirstSequenceOf87)...)
	content = append(content, segmentGroupBytes(1, 8, b.SequenceOf88)...)
	if len(b.SecondSequenceOf87) > 0 {
		content = append(content, segmentGroupBytes(2, 7, b.SecondSequenceOf87)...)
	}
	content = append(content, segmentGroupBytes(3, 6, b.SequenceOf86)...)
	return tlvBytes(asn1.Ctx(54, true), content)
}

// segmentGroupBytes builds an [n] SEQUENCE OF [segTag] OCTET STRING group.
func segmentGroupBytes(groupTag, segTag uint64, segments [][]byte) []byte {
	var content []byte
	for _, s := range segments {
		content = append(content, tlvBytes(asn1.Ctx(segTag, false), s)...)
	}
	return tlvBytes(asn1.Ctx(groupTag, true), content)
}

// tlvBytes emits a tag + definite-length + content.
func tlvBytes(tag, content []byte) []byte {
	out := make([]byte, 0, len(tag)+len(content)+4)
	out = append(out, tag...)
	out = append(out, asn1.EncodeLength(len(content))...)
	out = append(out, content...)
	return out
}

// DecodeBoundProfilePackage parses a BF36 BoundProfilePackage.
func DecodeBoundProfilePackage(raw []byte) (*BoundProfilePackage, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf36" {
		return nil, fmt.Errorf("rsp: BoundProfilePackage unexpected tag %X", t.Tag)
	}
	b := &BoundProfilePackage{}
	if v, ok := t.Find([]byte{0xbf, 0x23}); ok {
		b.InitialiseSecureChannelRequest = decodeInitialiseSecureChannelRequest(v)
	}
	b.FirstSequenceOf87 = groupSegments(t, 0, 7)
	b.SequenceOf88 = groupSegments(t, 1, 8)
	b.SecondSequenceOf87 = groupSegments(t, 2, 7)
	b.SequenceOf86 = groupSegments(t, 3, 6)
	return b, nil
}

func groupSegments(t asn1.TLV, groupTag uint64, segTag byte) [][]byte {
	group, ok := t.Find(asn1.Ctx(groupTag, true))
	if !ok {
		return nil
	}
	kids, err := group.Children()
	if err != nil {
		return nil
	}
	want := asn1.Ctx(uint64(segTag), false)
	var out [][]byte
	for _, k := range kids {
		if len(k.Tag) == len(want) && k.Tag[0] == want[0] {
			out = append(out, k.Value)
		}
	}
	return out
}

func decodeInitialiseSecureChannelRequest(t asn1.TLV) *InitialiseSecureChannelRequest {
	r := &InitialiseSecureChannelRequest{
		TransactionID: childBytes(t, asn1.Ctx(0, false)),
		SmdpOtpk:      childBytes(t, asn1.App(73, false)),
		SmdpSign:      childBytes(t, asn1.App(55, false)),
	}
	if v, ok := t.Find(asn1.Ctx(2, false)); ok {
		r.RemoteOpID, _ = v.Int()
	}
	if v, ok := t.Find(asn1.Ctx(6, true)); ok {
		r.ControlRefTemplate = ControlRefTemplate{
			KeyType: childBytes(v, asn1.Ctx(0, false)),
			KeyLen:  childBytes(v, asn1.Ctx(1, false)),
			HostID:  childBytes(v, asn1.Ctx(4, false)),
		}
	}
	return r
}
