package rsp

import (
	"fmt"

	"github.com/euicc-go/bertlv"

	"rsp42/internal/asn1"
)

// NotificationMetadata ------------------------------------------------------

// NotificationMetadata is the metadata attached to a notification (SGP.22 §5.7.9).
type NotificationMetadata struct {
	SeqNumber           int64
	Operation           uint8 // NotificationEvent bit mask
	NotificationAddress string
	ICCID               []byte
}

// Encode returns the BF2F encoding of the metadata.
func (m *NotificationMetadata) Encode() []byte {
	children := []*bertlv.TLV{
		asn1.Prim(asn1.Ctx(0, false), asn1.IntBytes(m.SeqNumber)),
		asn1.Prim(asn1.Ctx(1, false), []byte{0x00, m.Operation}),
		asn1.UTF8(m.NotificationAddress),
	}
	if len(m.ICCID) > 0 {
		children = append(children, asn1.Prim(asn1.App(26, false), m.ICCID))
	}
	return asn1.Marshal(asn1.New(asn1.Ctx(47, true), children...))
}

// DecodeNotificationMetadata parses a BF2F NotificationMetadata.
func DecodeNotificationMetadata(t asn1.TLV) (*NotificationMetadata, error) {
	m := &NotificationMetadata{
		NotificationAddress: childString(t, []byte{0x0c}),
		ICCID:               childBytes(t, asn1.App(26, false)),
	}
	if v, ok := t.Find(asn1.Ctx(0, false)); ok {
		m.SeqNumber, _ = v.Int()
	}
	if v, ok := t.Find(asn1.Ctx(1, false)); ok {
		if len(v.Value) >= 2 {
			m.Operation = v.Value[1]
		}
	}
	return m, nil
}

// ProfileInstallationResult -------------------------------------------------

// SuccessResult or ErrorResult of a profile installation.
type FinalResult struct {
	Success      bool
	AID          []byte
	SimaResponse []byte
	BppCommandID int64
	ErrorReason  int64
}

// ProfileInstallationResultData is the signed installation result payload.
type ProfileInstallationResultData struct {
	Raw           []byte
	TransactionID []byte
	Notification  *NotificationMetadata
	SmdpOID       string
	FinalResult   *FinalResult
}

// ProfileInstallationResult is the BF37 installation result (SGP.22 §5.7.6).
type ProfileInstallationResult struct {
	Data      *ProfileInstallationResultData
	DataRaw   []byte
	EuiccSign []byte
}

// DecodeProfileInstallationResult parses a BF37 ProfileInstallationResult.
func DecodeProfileInstallationResult(raw []byte) (*ProfileInstallationResult, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hexTag(t.Tag) != "bf37" {
		return nil, fmt.Errorf("rsp: ProfileInstallationResult unexpected tag %X", t.Tag)
	}
	out := &ProfileInstallationResult{EuiccSign: childBytes(t, asn1.App(55, false))}
	if d, ok := t.Find([]byte{0xbf, 0x27}); ok {
		out.DataRaw = d.Raw
		data := &ProfileInstallationResultData{
			Raw:           d.Raw,
			TransactionID: childBytes(d, asn1.Ctx(0, false)),
		}
		if nm, ok := d.Find([]byte{0xbf, 0x2f}); ok {
			data.Notification, _ = DecodeNotificationMetadata(nm)
		}
		if v, ok := d.Find([]byte{0x06}); ok {
			data.SmdpOID, _ = asn1.DecodeOID(v.Value)
		}
		if fr, ok := d.Find(asn1.Ctx(2, true)); ok {
			data.FinalResult = decodeFinalResult(fr)
		}
		out.Data = data
	}
	return out, nil
}

func decodeFinalResult(fr asn1.TLV) *FinalResult {
	// fr = A2 { A0|A1 { ... } }
	alt, ok := firstChild(fr)
	if !ok {
		return nil
	}
	res := &FinalResult{Success: len(alt.Tag) == 1 && alt.Tag[0] == 0xa0}
	if res.Success {
		res.AID = childBytes(alt, asn1.App(15, false))
		res.SimaResponse = childBytes(alt, asn1.TagOctetStr)
	} else {
		if v, ok := alt.Find(asn1.Ctx(0, false)); ok {
			res.BppCommandID, _ = v.Int()
		} else if v, ok := alt.Find(asn1.TagInteger); ok {
			res.BppCommandID, _ = v.Int()
		}
		if v, ok := alt.Find(asn1.Ctx(1, false)); ok {
			res.ErrorReason, _ = v.Int()
		} else if v, ok := alt.Find(asn1.TagInteger); ok {
			res.ErrorReason, _ = v.Int()
		}
	}
	return res
}

// OtherSignedNotification ---------------------------------------------------

// OtherSignedNotification carries enable/disable/delete notifications.
type OtherSignedNotification struct {
	Notification     *NotificationMetadata
	TbsRaw           []byte
	EuiccSignature   []byte
	EuiccCertificate []byte
	EumCertificate   []byte
}

// DecodeOtherSignedNotification parses an OtherSignedNotification structure.
func DecodeOtherSignedNotification(t asn1.TLV) (*OtherSignedNotification, error) {
	out := &OtherSignedNotification{EuiccSignature: childBytes(t, asn1.App(55, false))}
	if nm, ok := t.Find([]byte{0xbf, 0x2f}); ok {
		out.TbsRaw = nm.Raw
		out.Notification, _ = DecodeNotificationMetadata(nm)
	}
	seqs := certificateSequenceValues(t)
	if len(seqs) >= 1 {
		out.EuiccCertificate = seqs[0]
	}
	if len(seqs) >= 2 {
		out.EumCertificate = seqs[1]
	}
	return out, nil
}

// PendingNotification -------------------------------------------------------

// PendingNotification is either a ProfileInstallationResult or an
// OtherSignedNotification (SGP.22 §5.7.9).
type PendingNotification struct {
	InstallationResult *ProfileInstallationResult
	OtherSigned        *OtherSignedNotification
	Raw                []byte
}

// DecodePendingNotification parses a PendingNotification.
func DecodePendingNotification(raw []byte) (*PendingNotification, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	out := &PendingNotification{Raw: t.Raw}
	if len(t.Tag) == 1 && t.Tag[0] == 0xa0 {
		// HandleNotification wraps the CHOICE in an automatic [0] tag.
		inner, ok := firstChild(t)
		if !ok {
			return nil, fmt.Errorf("rsp: PendingNotification empty wrapper")
		}
		return DecodePendingNotification(inner.Raw)
	}
	switch hexTag(t.Tag) {
	case "bf37":
		out.InstallationResult, err = DecodeProfileInstallationResult(t.Raw)
		return out, err
	case "30":
		out.OtherSigned, err = DecodeOtherSignedNotification(t)
		return out, err
	default:
		return nil, fmt.Errorf("rsp: PendingNotification unexpected tag %X", t.Tag)
	}
}

// HandleNotification --------------------------------------------------------

// HandleNotification is the BF3D wrapper sent by the LPA to ES9+.HandleNotification.
type HandleNotification struct {
	Pending *PendingNotification
}

// DecodeHandleNotification parses a BF3D HandleNotification.
func DecodeHandleNotification(raw []byte) (*HandleNotification, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hexTag(t.Tag) != "bf3d" {
		return nil, fmt.Errorf("rsp: HandleNotification unexpected tag %X", t.Tag)
	}
	child, ok := firstChild(t)
	if !ok {
		return nil, fmt.Errorf("rsp: HandleNotification empty")
	}
	p, err := DecodePendingNotification(child.Raw)
	if err != nil {
		return nil, err
	}
	return &HandleNotification{Pending: p}, nil
}
