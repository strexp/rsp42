package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// genTestCert creates a self-signed CA (parent == nil) or a certificate signed
// by parent. It is intentionally minimal: it only needs to carry SGP.22-agnostic
// X.509 linkage (AKI/SKI, key usage) to exercise chain verification.
func genTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          []byte(cn + "-ski"),
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func TestValidateEUICCChainWithIntermediate(t *testing.T) {
	ci, ciKey := genTestCert(t, "CI", true, nil, nil)
	inter, interKey := genTestCert(t, "Intermediate", true, ci, ciKey)
	eum, eumKey := genTestCert(t, "EUM", true, inter, interKey)
	euicc, _ := genTestCert(t, "eUICC", false, eum, eumKey)

	// Without the intermediate the chain cannot reach the CI.
	require.Error(t, validateEUICCChain(euicc, eum, nil, ci, ci.SubjectKeyId))

	// With otherCertsInChain the chain verifies.
	require.NoError(t, validateEUICCChain(euicc, eum, []*x509.Certificate{inter}, ci, ci.SubjectKeyId))

	// An unrelated trust anchor is rejected.
	other, _ := genTestCert(t, "Other", true, nil, nil)
	require.Error(t, validateEUICCChain(euicc, eum, []*x509.Certificate{inter}, other, other.SubjectKeyId))
}

func TestValidateEUICCChainDirect(t *testing.T) {
	ci, ciKey := genTestCert(t, "CI", true, nil, nil)
	eum, eumKey := genTestCert(t, "EUM", true, ci, ciKey)
	euicc, _ := genTestCert(t, "eUICC", false, eum, eumKey)

	require.NoError(t, validateEUICCChain(euicc, eum, nil, ci, ci.SubjectKeyId))
	// EUM must be signed by the selected CI (AKI/SKI shortcut).
	other, _ := genTestCert(t, "Other", true, nil, nil)
	require.Error(t, validateEUICCChain(euicc, eum, nil, other, other.SubjectKeyId))
}
