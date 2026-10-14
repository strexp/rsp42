package kms

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

var testKEK = []byte("0123456789abcdef0123456789abcdef")

func TestFileProviderEncryptDecrypt(t *testing.T) {
	p, err := NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)

	secret := []byte("server-challenge-16")
	ct, err := p.Encrypt(secret)
	require.NoError(t, err)
	require.NotEqual(t, secret, ct)

	pt, err := p.Decrypt(ct)
	require.NoError(t, err)
	require.Equal(t, secret, pt)

	// Non-deterministic (fresh nonce each time).
	ct2, err := p.Encrypt(secret)
	require.NoError(t, err)
	require.NotEqual(t, ct, ct2)

	// Tampered ciphertext fails authentication.
	ct[len(ct)-1] ^= 0xff
	_, err = p.Decrypt(ct)
	require.Error(t, err)
}

func TestLoadSigner(t *testing.T) {
	p, err := NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)

	key, err := p.LoadSigner("../../testdata/sgp26/SM-DP+/DPauth/SK_DPauth_NIST.pem")
	require.NoError(t, err)
	_, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok)

	_, err = p.LoadSigner("../../testdata/sgp26/CertificateIssuer/CERT_CI_NIST.der")
	require.Error(t, err)
}

func TestKEKSources(t *testing.T) {
	// hex
	_, err := NewFileProviderFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	_, err = NewFileProviderFromHex("not-hex")
	require.Error(t, err)

	// file
	path := filepath.Join(t.TempDir(), "kek.bin")
	require.NoError(t, os.WriteFile(path, testKEK, 0o600))
	_, err = NewFileProvider(path)
	require.NoError(t, err)

	// length checks
	_, err = NewFileProviderFromKEK(make([]byte, 16))
	require.Error(t, err)
	_, err = NewFileProviderFromKEK(make([]byte, 32))
	require.NoError(t, err)
}

// TestProviderInterfaceSplit pins the intended seam: a certificate manager only
// needs a SignerLoader and the session/personalization stores only need a
// Sealer, so a future non-file provider (HSM, vault) does not have to implement
// path-based key loading to provide at-rest encryption, or vice versa.
func TestProviderInterfaceSplit(t *testing.T) {
	provider, err := NewFileProviderFromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	var signerOnly SignerLoader = provider
	var sealerOnly Sealer = provider
	var both Provider = provider
	require.NotNil(t, signerOnly)
	require.NotNil(t, sealerOnly)
	require.NotNil(t, both)

	sealed, err := sealerOnly.Encrypt([]byte("secret"))
	require.NoError(t, err)
	opened, err := sealerOnly.Decrypt(sealed)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), opened)
}
