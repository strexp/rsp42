package rsp

import (
	"encoding/hex"
	"fmt"

	"rsp42/internal/asn1"
)

// InitialiseSecureChannelRequest -------------------------------------------

// ControlRefTemplate is the key-agreement control reference template.
type ControlRefTemplate struct {
	KeyType []byte
	KeyLen  []byte
	HostID  []byte
}

// InitialiseSecureChannelRequest is the first BPP element (SGP.22 §5.5.1).
type InitialiseSecureChannelRequest struct {
	RemoteOpID         int64
	TransactionID      []byte
	ControlRefTemplate ControlRefTemplate
	SmdpOtpk           []byte
	SmdpSign           []byte
}

// remoteOpID returns the effective remote operation id: 1 unless the caller set
// one explicitly. Encode and SignedBytes both go through it, so the signed bytes
// and the encoded element can never disagree (SGP.22 §5.5.4).
func (r *InitialiseSecureChannelRequest) remoteOpID() int64 {
	if r.RemoteOpID == 0 {
		return 1
	}
	return r.RemoteOpID
}

// Encode returns the BF23 encoding of the request. It does not modify the
// receiver.
func (r *InitialiseSecureChannelRequest) Encode() []byte {
	crt := asn1.New(asn1.Ctx(6, true),
		asn1.Prim(asn1.Ctx(0, false), r.ControlRefTemplate.KeyType),
		asn1.Prim(asn1.Ctx(1, false), r.ControlRefTemplate.KeyLen),
		asn1.Prim(asn1.Ctx(4, false), r.ControlRefTemplate.HostID),
	)
	return asn1.Marshal(asn1.New(asn1.Ctx(35, true),
		asn1.Prim(asn1.Ctx(2, false), asn1.IntBytes(r.remoteOpID())),
		asn1.Prim(asn1.Ctx(0, false), r.TransactionID),
		crt,
		asn1.Prim(asn1.App(73, false), r.SmdpOtpk),
		asn1.Prim(asn1.App(55, false), r.SmdpSign),
	))
}

// SignedBytes returns the exact bytes signed by SK.DPpb for the BF23 element
// (SGP.22 §2.5.4): remoteOpId || transactionId || controlRefTemplate ||
// smdpOtpk, followed by wrap(0x5F49, euiccOtpk).
func (r *InitialiseSecureChannelRequest) SignedBytes(euiccOtpk []byte) []byte {
	crt := asn1.New(asn1.Ctx(6, true),
		asn1.Prim(asn1.Ctx(0, false), r.ControlRefTemplate.KeyType),
		asn1.Prim(asn1.Ctx(1, false), r.ControlRefTemplate.KeyLen),
		asn1.Prim(asn1.Ctx(4, false), r.ControlRefTemplate.HostID),
	)
	out := concat(
		asn1.Marshal(asn1.Prim(asn1.Ctx(2, false), asn1.IntBytes(r.remoteOpID()))),
		asn1.Marshal(asn1.Prim(asn1.Ctx(0, false), r.TransactionID)),
		asn1.Marshal(crt),
		asn1.Marshal(asn1.Prim(asn1.App(73, false), r.SmdpOtpk)),
	)
	if len(euiccOtpk) > 0 {
		out = append(out, tlvBytes(asn1.App(73, false), euiccOtpk)...)
	}
	return out
}

// ConfigureISDPRequest ------------------------------------------------------

// ConfigureISDPRequest is the second BPP element (SGP.22 §5.5.2).
type ConfigureISDPRequest struct {
	DpOID string // when empty, an empty BF24 is encoded
}

// Encode returns the BF24 encoding of the request. It reports an error when
// DpOID is not a valid dotted OBJECT IDENTIFIER (X.690 §8.19) instead of
// panicking, because the value comes from configuration.
func (r *ConfigureISDPRequest) Encode() ([]byte, error) {
	if r.DpOID == "" {
		return asn1.Marshal(asn1.New(asn1.Ctx(36, true))), nil
	}
	oid, err := asn1.EncodeOID(r.DpOID)
	if err != nil {
		return nil, err
	}
	prop := asn1.New(asn1.Ctx(24, true), asn1.Prim(asn1.Ctx(0, false), oid))
	return asn1.Marshal(asn1.New(asn1.Ctx(36, true), prop)), nil
}

// StoreMetadataRequest ------------------------------------------------------

// PPRIDBits encodes PPR ids as the PprIds BIT STRING content bytes (MSB-first;
// PPR id 1 = ppr1, 2 = ppr2, per SGP.22 §2.4a). It returns nil for no ids.
func PPRIDBits(ids []int) []byte {
	if len(ids) == 0 {
		return nil
	}
	maxID := 0
	for _, id := range ids {
		if id > maxID {
			maxID = id
		}
	}
	b := make([]byte, maxID/8+1)
	for _, id := range ids {
		if id >= 0 {
			b[id/8] |= 0x80 >> (uint(id) % 8)
		}
	}
	return b
}

// NotificationConfigurationInformation configures a notification address.
type NotificationConfigurationInformation struct {
	Operation uint8 // bit mask of NotificationEvent
	Address   string
}

// StoreMetadataRequest is the BPP metadata element (SGP.22 §5.5.3).
type StoreMetadataRequest struct {
	ICCID               []byte // EF.ICCID nibble-swapped form
	ServiceProviderName string
	ProfileName         string
	ProfileClass        *int64
	Notifications       []NotificationConfigurationInformation
	IconType            *int64
	Icon                []byte
	ProfileOwner        []byte // raw OperatorID (B7) value, if any
	PPRIds              []byte // raw BIT STRING content (without unused byte), if any
	ServiceSpecificData []byte // raw serviceSpecificDataNotStoredInEuicc (BF23) TLV, if any
}

// Encode returns the BF25 encoding of the request.
func (r *StoreMetadataRequest) Encode() []byte {
	var content []byte
	content = append(content, tlvBytes(asn1.App(26, false), r.ICCID)...)
	content = append(content, tlvBytes(asn1.Ctx(17, false), []byte(r.ServiceProviderName))...)
	content = append(content, tlvBytes(asn1.Ctx(18, false), []byte(r.ProfileName))...)
	if r.IconType != nil {
		content = append(content, tlvBytes(asn1.Ctx(19, false), asn1.IntBytes(*r.IconType))...)
	}
	if len(r.Icon) > 0 {
		content = append(content, tlvBytes(asn1.Ctx(20, false), r.Icon)...)
	}
	if r.ProfileClass != nil {
		content = append(content, tlvBytes(asn1.Ctx(21, false), asn1.IntBytes(*r.ProfileClass))...)
	}
	if len(r.Notifications) > 0 {
		var entries []byte
		for _, n := range r.Notifications {
			var item []byte
			item = append(item, tlvBytes(asn1.Ctx(0, false), []byte{0x00, n.Operation})...)
			item = append(item, tlvBytes(asn1.Ctx(1, false), []byte(n.Address))...)
			entries = append(entries, tlvBytes([]byte{0x30}, item)...)
		}
		content = append(content, tlvBytes(asn1.Ctx(22, true), entries)...)
	}
	if len(r.ProfileOwner) > 0 {
		content = append(content, tlvBytes(asn1.Ctx(23, false), r.ProfileOwner)...)
	}
	if len(r.PPRIds) > 0 {
		content = append(content, tlvBytes(asn1.Ctx(25, false), append([]byte{0x00}, r.PPRIds...))...)
	}
	if len(r.ServiceSpecificData) > 0 {
		content = append(content, r.ServiceSpecificData...)
	}
	return tlvBytes(asn1.Ctx(37, true), content)
}

// ActivationCodeRetrievalInfo builders (SGP.22 §4.9.2). Each returns the
// serviceSpecificDataNotStoredInEuicc (BF23) element to embed in
// StoreMetadataRequest.ServiceSpecificData.

// acrOID is the SGP.22 §4.9.2 vendor extension OID (BF23 serviceSpecificData).
// It is a compile-time constant, so a bad literal is a programming error caught
// by TestACROIDLiteral.
var acrOID = asn1.MustEncodeOID("2.23.146.1.3.1.1")

func acrVendorExtension(inner []byte) []byte {
	entry := tlvBytes([]byte{0x30}, concat(
		tlvBytes(asn1.Ctx(0, false), acrOID),
		tlvBytes(asn1.Ctx(1, true), inner),
	))
	return tlvBytes(asn1.Ctx(35, true), entry)
}

// ACRRedownload builds the activationCodeForProfileRedownload variant.
func ACRRedownload(activationCode string) []byte {
	return acrVendorExtension(tlvBytes([]byte{0x81}, []byte(activationCode)))
}

// ACRAvailable builds the activationCodeRetrievalAvailable variant.
func ACRAvailable() []byte {
	return acrVendorExtension([]byte{0x82, 0x01, 0xff})
}

// DecodeStoreMetadataRequest parses a BF25 StoreMetadataRequest.
func DecodeStoreMetadataRequest(t asn1.TLV) (*StoreMetadataRequest, error) {
	r := &StoreMetadataRequest{
		ICCID:               childBytes(t, asn1.App(26, false)),
		ServiceProviderName: childString(t, asn1.Ctx(17, false)),
		ProfileName:         childString(t, asn1.Ctx(18, false)),
	}
	if v, ok := t.Find(asn1.Ctx(21, false)); ok {
		n, _ := v.Int()
		r.ProfileClass = &n
	}
	if v, ok := t.Find(asn1.Ctx(22, true)); ok {
		kids, _ := v.Children()
		for _, k := range kids {
			op := childBytes(k, asn1.Ctx(0, false))
			var mask uint8
			if len(op) >= 2 {
				mask = op[1]
			}
			r.Notifications = append(r.Notifications, NotificationConfigurationInformation{
				Operation: mask,
				Address:   childString(k, asn1.Ctx(1, false)),
			})
		}
	}
	return r, nil
}

// ReplaceSessionKeysRequest -------------------------------------------------

// ReplaceSessionKeysRequest carries the PPK key material (SGP.22 §5.5.5).
type ReplaceSessionKeysRequest struct {
	InitialMacChainingValue []byte
	PPKEnc                  []byte
	PPKCmac                 []byte
}

// Encode returns the BF26 encoding of the request.
func (r *ReplaceSessionKeysRequest) Encode() []byte {
	return asn1.Marshal(asn1.New(asn1.Ctx(38, true),
		asn1.Octet(r.InitialMacChainingValue),
		asn1.Octet(r.PPKEnc),
		asn1.Octet(r.PPKCmac),
	))
}

// GetBoundProfilePackageRequest --------------------------------------------

// GetBoundProfilePackageRequest is sent from the LPA to ES9+.
type GetBoundProfilePackageRequest struct {
	TransactionID        []byte
	PrepareDownloadRaw   []byte
	PrepareDownload      *PrepareDownloadResponseOk
	PrepareDownloadError *PrepareDownloadResponseError
}

// DecodeGetBoundProfilePackageRequest parses a BF3A GetBoundProfilePackageRequest.
func DecodeGetBoundProfilePackageRequest(raw []byte) (*GetBoundProfilePackageRequest, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf3a" {
		return nil, fmt.Errorf("rsp: GetBoundProfilePackageRequest unexpected tag %X", t.Tag)
	}
	out := &GetBoundProfilePackageRequest{TransactionID: childBytes(t, asn1.Ctx(0, false))}
	pd, ok := t.Find([]byte{0xbf, 0x21})
	if !ok {
		return nil, fmt.Errorf("rsp: GetBoundProfilePackageRequest missing prepareDownloadResponse")
	}
	// prepareDownloadResponse [33] is a CHOICE, so the context tag is explicit
	// and the PrepareDownloadResponse is nested inside it.
	inner := unwrapExplicit(pd, []byte{0xbf, 0x21})
	out.PrepareDownloadRaw = inner
	out.PrepareDownload, out.PrepareDownloadError, err = DecodePrepareDownloadResponse(inner)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// unwrapExplicit returns the inner TLV of an explicitly tagged CHOICE-typed
// field (e.g. `prepareDownloadResponse [33]`). It is tolerant of a single-tagged
// form, returning the field itself when it already carries the inner tag.
func unwrapExplicit(field asn1.TLV, innerTag []byte) []byte {
	if c, ok := field.First(); ok && hex.EncodeToString(c.Tag) == hex.EncodeToString(innerTag) {
		return c.Raw
	}
	return field.Raw
}

// AuthenticateClientRequest -------------------------------------------------

// AuthenticateClientRequest is sent from the LPA to ES9+.
type AuthenticateClientRequest struct {
	TransactionID        []byte
	AuthenticateResponse []byte // raw BF38
}

// DecodeAuthenticateClientRequest parses a BF3B AuthenticateClientRequest.
func DecodeAuthenticateClientRequest(raw []byte) (*AuthenticateClientRequest, error) {
	t, _, err := asn1.ReadTLV(raw)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(t.Tag) != "bf3b" {
		return nil, fmt.Errorf("rsp: AuthenticateClientRequest unexpected tag %X", t.Tag)
	}
	out := &AuthenticateClientRequest{TransactionID: childBytes(t, asn1.Ctx(0, false))}
	if v, ok := t.Find([]byte{0xbf, 0x38}); ok {
		// authenticateServerResponse [56] is a CHOICE, so the context tag is
		// explicit and the AuthenticateServerResponse is nested inside it.
		out.AuthenticateResponse = unwrapExplicit(v, []byte{0xbf, 0x38})
	}
	return out, nil
}
