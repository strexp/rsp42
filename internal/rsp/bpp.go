package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// BoundProfilePackage is the BF36 shell assembled by the SM-DP+ (SGP.22 §5.5).
//
// Every segment slice holds complete SCP03t data-block TLVs (tag + length +
// protected data + MAC), exactly as crypto.ProtectBPP returns them; the group
// tags in Assemble only add the [0]/[1]/[2]/[3] sequence wrapper.
type BoundProfilePackage struct {
	InitialiseSecureChannelRequest *InitialiseSecureChannelRequest
	FirstSequenceOf87              [][]byte // complete '87' TLVs: protected ConfigureISDP (BF24)
	SequenceOf88                   [][]byte // complete '88' TLVs: protected StoreMetadata (BF25)
	SecondSequenceOf87             [][]byte // complete '87' TLVs: protected ReplaceSessionKeys (BF26), optional
	SequenceOf86                   [][]byte // complete '86' TLVs: protected UPP segments
}

// Assemble encodes the BoundProfilePackage to its wire form. It concatenates
// the already-encoded children byte-for-byte so the raw BSP segments and the
// signed BF23 element are preserved exactly.
func (b *BoundProfilePackage) Assemble() []byte {
	var content []byte
	content = append(content, b.InitialiseSecureChannelRequest.Encode()...)
	content = append(content, segmentGroupBytes(0, b.FirstSequenceOf87)...)
	content = append(content, segmentGroupBytes(1, b.SequenceOf88)...)
	if len(b.SecondSequenceOf87) > 0 {
		content = append(content, segmentGroupBytes(2, b.SecondSequenceOf87)...)
	}
	content = append(content, segmentGroupBytes(3, b.SequenceOf86)...)
	return asn1.RawTagged(asn1.Ctx(54, true), content)
}

// segmentGroupBytes builds an [n] SEQUENCE OF [segTag] OCTET STRING group.
//
// Each element of segments is already a complete SCP03t data block TLV
// (tag '87'/'88'/'86', length, protected data, MAC) as produced by
// crypto.EncryptAndMAC/crypto.MACOnly. SGP.22 Annex H types the group as
// "SEQUENCE OF [7]/[8]/[6] OCTET STRING -- sequence of '87'/'88'/'86' TLVs",
// i.e. the OCTET STRING tag *is* the SGP.02 SCP03t data-block tag, so the
// segment is appended verbatim; wrapping it in a second OCTET STRING (as this
// function used to) makes a real eUICC reject the package with
// scp03tSecurityError at the first protected block (see
// docs/real-card-test-report.md, R5).
func segmentGroupBytes(groupTag uint64, segments [][]byte) []byte {
	var content []byte
	for _, s := range segments {
		content = append(content, s...)
	}
	return asn1.RawTagged(asn1.Ctx(groupTag, true), content)
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

// groupSegments collects the SCP03t segments of one group. Each group child is
// itself the data block TLV (tag '87'/'88'/'86' + length + protected data +
// MAC), so its raw form is what crypto.DemacAndDecrypt/DemacOnly expects.
func groupSegments(t asn1.TLV, groupTag uint64, segTag byte) [][]byte {
	group, ok := t.Find(asn1.Ctx(groupTag, true))
	if !ok {
		return nil
	}
	kids, err := group.Children()
	if err != nil {
		return nil
	}
	var out [][]byte
	want := asn1.Ctx(uint64(segTag), false)
	for _, k := range kids {
		if len(k.Tag) == len(want) && k.Tag[0] == want[0] {
			out = append(out, k.Raw)
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
