package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func sha256sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func TestSignVerifyRaw(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	data := []byte("the quick brown fox")

	sig, err := SignRaw(priv, data)
	require.NoError(t, err)
	require.Len(t, sig, 64)
	require.True(t, VerifyRaw(&priv.PublicKey, data, sig))
	require.False(t, VerifyRaw(&priv.PublicKey, []byte("tampered"), sig))

	sig[0] ^= 0xff
	require.False(t, VerifyRaw(&priv.PublicKey, data, sig))
}

func TestDerRawRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	data := []byte("hello")

	raw, err := SignRaw(priv, data)
	require.NoError(t, err)
	der, err := RawToDer(elliptic.P256(), raw)
	require.NoError(t, err)

	back, err := DerToRaw(elliptic.P256(), der)
	require.NoError(t, err)
	require.Equal(t, raw, back)

	// The DER form must verify with the standard library.
	require.True(t, ecdsa.VerifyASN1(&priv.PublicKey, sha256sum(data), der))
}

func TestECPointRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	enc, err := ECPointUncompressed(&priv.PublicKey)
	require.NoError(t, err)
	require.Len(t, enc, 65)
	require.Equal(t, byte(0x04), enc[0])
	got, err := ParseECPoint(elliptic.P256(), enc)
	require.NoError(t, err)
	require.True(t, priv.PublicKey.Equal(got))
}
