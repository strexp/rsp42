package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProtectBPPRoundTrip exercises the generation half of the BPP protection
// pair: ProtectBPP must produce segments that UnprotectBPP — and therefore the
// eUICC — decodes back to the exact plaintext elements, including when a
// payload needs several BSP segments.
func TestProtectBPPRoundTrip(t *testing.T) {
	shared := bytes.Repeat([]byte{0x11}, 32)
	hostID := []byte("00000000")
	eid := bytes.Repeat([]byte{0x22}, 16)

	configureISDP := bytes.Repeat([]byte{0xA1}, 64)
	storeMetadata := bytes.Repeat([]byte{0xB2}, 300)
	replaceSessionKeys := bytes.Repeat([]byte{0xC3}, 32)
	// Larger than one BSP segment so the segmenting path is covered.
	upp := bytes.Repeat([]byte{0xD4}, 5000)

	res, err := ProtectBPP(shared, hostID, eid, configureISDP, storeMetadata, replaceSessionKeys, upp, nil)
	require.NoError(t, err)

	gotCfg, gotSMD, gotRSK, gotUPP, err := UnprotectBPP(shared, hostID, eid, res, nil)
	require.NoError(t, err)
	require.Equal(t, configureISDP, gotCfg)
	require.Equal(t, storeMetadata, gotSMD)
	require.Equal(t, replaceSessionKeys, gotRSK)
	require.Equal(t, upp, gotUPP)
}

// TestProtectBPPWithoutReplaceSessionKeys pins the optional BF26 element: when
// the caller passes none, UnprotectBPP reports none.
func TestProtectBPPWithoutReplaceSessionKeys(t *testing.T) {
	shared := bytes.Repeat([]byte{0x33}, 32)
	hostID := []byte("00000000")
	eid := bytes.Repeat([]byte{0x44}, 16)

	res, err := ProtectBPP(shared, hostID, eid, []byte{1}, []byte{2}, nil, []byte{3}, nil)
	require.NoError(t, err)

	_, _, rsk, _, err := UnprotectBPP(shared, hostID, eid, res, nil)
	require.NoError(t, err)
	require.Empty(t, rsk)
}
