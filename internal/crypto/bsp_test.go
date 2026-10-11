package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func h2b(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// Static BSP test vectors (key derivation and ciphering).
func TestBSPKDF(t *testing.T) {
	sharedSecret := h2b(t, "8902dca391bbb22570fe60c176076246f568b1941265dff1d729e63039658089")
	eid := h2b(t, "89049032123451234512345678901335")
	m := BSPDerive(sharedSecret, 0x88, 16, repeat(0x80, 8), eid, 16)
	require.Equal(t, h2b(t, "d782d575b22a38334556a3d9a1e2ae6b"), m.SEnc)
	require.Equal(t, h2b(t, "a35addc192ae8f934e2932116c7e89e7"), m.SMac)
	require.Equal(t, h2b(t, "734bc93ddb10c71c5ad13d420dc08b5b"), m.InitialMCV)
}

func TestBSPKDFMode51(t *testing.T) {
	sharedSecret := h2b(t, "c9a993dd4879a8f7161f2085410edd4f9652f1df37be097ba96ba2ca6be528fe")
	eid := h2b(t, "89049032123451234512345678901235")
	m := BSPDerive(sharedSecret, 0x88, 16, repeat(0x80, 8), eid, 16)
	require.Equal(t, h2b(t, "472f5bfadd97f21d34f3ce9b51b92751"), m.SEnc)
	require.Equal(t, h2b(t, "9ec07f5b36a13e12a991d66e294e6242"), m.SMac)
	require.Equal(t, h2b(t, "406d507b448a699e7a36a38494debbde"), m.InitialMCV)
}

func TestBSPCiphering(t *testing.T) {
	bi, err := NewBSPInstanceRaw(
		h2b(t, "472f5bfadd97f21d34f3ce9b51b92751"),
		h2b(t, "9ec07f5b36a13e12a991d66e294e6242"),
		h2b(t, "406d507b448a699e7a36a38494debbde"),
	)
	require.NoError(t, err)

	out, err := bi.EncryptAndMAC(0x87, h2b(t, "bf2400"))
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, h2b(t, "8718f6fe031e4b9cfe87c8e1e62f3fde85c49412d7722a6a2d89"), out[0])

	out, err = bi.MACOnly(0x88, h2b(t, "bf252d5a0a98001032547698103214910947534d415f54455354921147534d415f544553545f50524f46494c45950100"))
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, h2b(t, "8838bf252d5a0a98001032547698103214910947534d415f54455354921147534d415f544553545f50524f46494c459501008a62cc9adbb5ccbc"), out[0])

	out, err = bi.EncryptAndMAC(0x87, h2b(t, "bf26368010000102030405060708090a0b0c0d0e0f8110010102030405060708090a0b0c0d0e0f8210020102030405060708090a0b0c0d0e0f"))
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, h2b(t, "8748a14c800a001992351cd46ad2945654674369701d82b7b46567652bc8fbed234939fc57fba748015525fd6c651e9d3d1330652d42a0cfad950e912122af4ec5362d3c0bc535729c40"), out[0])
}

func TestBSPMACOnlyCounterAdvances(t *testing.T) {
	// After a MAC-only segment the ICV counter must have advanced so that a
	// following encrypted segment uses block number 2.
	bi, err := NewBSPInstanceRaw(repeat(0x01, 16), repeat(0x02, 16), repeat(0x03, 16))
	require.NoError(t, err)
	_, err = bi.MACOnlyOne(0x88, []byte{0x01})
	require.NoError(t, err)
	require.Equal(t, uint32(2), bi.blockNr)
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
