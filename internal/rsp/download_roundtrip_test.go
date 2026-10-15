package rsp

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"rsp42/internal/asn1"
)

// TestStoreMetadataRequestRoundTrip pins that DecodeStoreMetadataRequest is the
// inverse of Encode for every member the encoder writes. The decoder used to
// read only ICCID/SPN/ProfileName/ProfileClass/Notifications, so a decode of a
// generated element silently lost five field groups.
func TestStoreMetadataRequestRoundTrip(t *testing.T) {
	iconType := int64(1)
	class := int64(2)
	want := &StoreMetadataRequest{
		ICCID:               []byte{0x98, 0x00, 0x10, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x14},
		ServiceProviderName: "SPN",
		ProfileName:         "Name",
		IconType:            &iconType,
		Icon:                []byte{0xDE, 0xAD},
		ProfileClass:        &class,
		Notifications: []NotificationConfigurationInformation{
			{Operation: 0x40, Address: "a"},
			{Operation: 0x20, Address: "b"},
		},
		ProfileOwner:        []byte{0x01, 0x02, 0x03},
		PPRIds:              PPRIDBits([]int{1, 2}),
		ServiceSpecificData: ACRAvailable(),
	}

	raw := want.Encode()
	tlv, rest, err := asn1.ReadTLV(raw)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, "bf25", hex.EncodeToString(tlv.Tag))

	got, err := DecodeStoreMetadataRequest(tlv)
	require.NoError(t, err)

	require.Equal(t, want.ICCID, got.ICCID)
	require.Equal(t, want.ServiceProviderName, got.ServiceProviderName)
	require.Equal(t, want.ProfileName, got.ProfileName)
	require.NotNil(t, got.IconType)
	require.Equal(t, iconType, *got.IconType)
	require.Equal(t, want.Icon, got.Icon)
	require.NotNil(t, got.ProfileClass)
	require.Equal(t, class, *got.ProfileClass)
	require.Equal(t, want.Notifications, got.Notifications)
	require.Equal(t, want.ProfileOwner, got.ProfileOwner)
	require.Equal(t, want.PPRIds, got.PPRIds)
	require.Equal(t, want.ServiceSpecificData, got.ServiceSpecificData)

	// Re-encoding the decoded value must reproduce the same bytes.
	require.Equal(t, raw, got.Encode())
}

// TestStoreMetadataRequestDecodeMinimal pins the decoder on the smallest valid
// element (only the mandatory members), where every optional field stays empty.
func TestStoreMetadataRequestDecodeMinimal(t *testing.T) {
	raw := (&StoreMetadataRequest{ICCID: []byte{0x01}, ProfileName: "p"}).Encode()
	tlv, _, err := asn1.ReadTLV(raw)
	require.NoError(t, err)

	got, err := DecodeStoreMetadataRequest(tlv)
	require.NoError(t, err)
	require.Nil(t, got.IconType)
	require.Nil(t, got.ProfileClass)
	require.Empty(t, got.Icon)
	require.Empty(t, got.ProfileOwner)
	require.Empty(t, got.PPRIds)
	require.Empty(t, got.ServiceSpecificData)
	require.Empty(t, got.Notifications)
}

// TestPPRIDListRoundTrip pins the PprIds bitmap codec against the values that
// appear on the wire (ppr1 = bit 1, ppr2 = bit 2, SGP.22 §2.8.1.1).
func TestPPRIDListRoundTrip(t *testing.T) {
	for _, ids := range [][]int{nil, {1}, {2}, {1, 2}, {0, 2}} {
		bits := PPRIDBits(ids)
		if len(ids) == 0 {
			require.Nil(t, bits)
			require.Empty(t, PPRIDList(bits))
			continue
		}
		require.Equal(t, ids, PPRIDList(bits), "ids %v", ids)
	}
	// The on-the-wire forms seen from a real eUICC (SGP.26 Variant O) and from
	// rsp42's own StoreMetadata encoder.
	require.Equal(t, []int{1}, PPRIDList([]byte{0x40}))
	require.Equal(t, []int{1, 2}, PPRIDList([]byte{0x60}))
	require.Equal(t, []byte{0x40}, PPRBitStringContent([]byte{0x00, 0x40}))
	require.Nil(t, PPRBitStringContent([]byte{0x00}))
	require.Nil(t, PPRBitStringContent(nil))
}
