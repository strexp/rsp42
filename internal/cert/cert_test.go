package cert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"rsp42/internal/kms"
)

const testRoot = "../../testdata/sgp26"

var testKEK = []byte("0123456789abcdef0123456789abcdef")

func testOptions() Options {
	return Options{
		RootDir: testRoot,
		CI:      "CertificateIssuer",
		EUM:     "EUM",
		EUICC:   "eUICC",
		DPAuth:  "SM-DP+/DPauth",
		DPPb:    "SM-DP+/DPpb",
		DPTLS:   "SM-DP+/DPtls",
		DSAuth:  "SM-DS/DSauth",
		DSTLS:   "SM-DS/DStls",
		Curve:   "nist",
		DPFQDN:  "testsmdpplus1.example.com",
		DPOID:   "2.999.10",
		DSFQDN:  "testrootsmds.example.com",
		DSOID:   "2.999.15",
	}
}

func mustManager(t *testing.T) *Manager {
	t.Helper()
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	m, err := Load(testOptions(), provider)
	require.NoError(t, err)
	return m
}

func TestLoadSetsMultipleIdentities(t *testing.T) {
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	opts := testOptions()
	m, err := LoadSets([]Options{opts, opts}, provider)
	require.NoError(t, err)
	require.Equal(t, 2, m.Count())

	// The eUICC-proposed CI key id (its SubjectKeyIdentifier) selects the first
	// identity.
	id, err := m.SelectIdentity([][]byte{m.CI().SubjectKeyId})
	require.NoError(t, err)
	require.Equal(t, m.CI().SubjectKeyId, id.CI.SubjectKeyId)

	// Unknown key ids are rejected.
	_, err = m.SelectIdentity([][]byte{{0xaa, 0xbb}})
	require.Error(t, err)

	// Lookup helpers.
	require.NotNil(t, m.IdentityByCIKeyID(m.CI().SubjectKeyId))
	require.Nil(t, m.IdentityByCIKeyID([]byte("nope")))
	require.NotNil(t, m.CIByAKI(m.CI().SubjectKeyId))
	require.Nil(t, m.CIByAKI([]byte("nope")))
}

func TestLoadValidChain(t *testing.T) {
	m := mustManager(t)
	require.Empty(t, m.Warnings())
	require.NotNil(t, m.CI())
	require.NotNil(t, m.DPAuth())
	require.NotNil(t, m.DPPb())
	require.NotNil(t, m.DSAuth())

	require.NoError(t, RequireRole(m.DPAuth(), OIDRoleDPAuth))
	require.NoError(t, RequireRole(m.EUM(), OIDRoleEUM))
	require.NoError(t, RequireRole(m.EUICC(), OIDRoleEUICC))

	ok, err := HasRegisteredID(m.DPAuth(), "2.999.10")
	require.NoError(t, err)
	require.True(t, ok)
	a, err := HasRegisteredID(m.DPAuth(), "2.999.99")
	require.NoError(t, err)
	require.False(t, a)

	// The eUICC chain verifies up to the CI via the EUM.
	require.NoError(t, VerifySignatureChain(m.EUICC(), []*x509.Certificate{m.EUM(), m.CI()}))
}

func TestWrongRoleRejected(t *testing.T) {
	m := mustManager(t)
	require.Error(t, RequireRole(m.DPAuth(), OIDRoleDPPb))
}

func TestEUMConstraints(t *testing.T) {
	m := mustManager(t)
	c, err := ParseEUMConstraints(m.EUM())
	require.NoError(t, err)
	require.Equal(t, "RSP Test EUM", c.OrganizationName)
	require.Equal(t, "89049032", c.IIN)

	require.NoError(t, c.ValidateEID("89049032123451234512345678901235"))
	require.Error(t, c.ValidateEID("99999932123451234512345678901235"))
}

func TestSelectCI(t *testing.T) {
	m := mustManager(t)
	ski := m.CI().SubjectKeyId

	ci, err := m.SelectCI([][]byte{ski})
	require.NoError(t, err)
	require.Equal(t, m.CI().Subject.String(), ci.Subject.String())

	prefixed := append([]byte{0x04}, ski...)
	ci, err = m.SelectCI([][]byte{{0xde, 0xad}, prefixed})
	require.NoError(t, err)
	require.Equal(t, m.CI().Subject.String(), ci.Subject.String())

	_, err = m.SelectCI([][]byte{{0x00, 0x01, 0x02}})
	require.Error(t, err)
}

func TestExpiredCertificateRejected(t *testing.T) {
	ci, err := LoadCertificate(testRoot + "/CertificateIssuer/CERT_CI_NIST.der")
	require.NoError(t, err)
	provider, err := kms.NewFileProviderFromKEK(testKEK)
	require.NoError(t, err)
	ciKey, err := provider.ECDSAKey(testRoot + "/CertificateIssuer/SK_CI_NIST.pem")
	require.NoError(t, err)

	expired := createCert(t, ci, ciKey, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	require.Error(t, CheckValidity(expired, time.Now(), false))
	require.NoError(t, CheckValidity(expired, time.Now(), true))
}

func TestNameConstraintsMissingIIN(t *testing.T) {
	c := &EUMConstraints{}
	require.NoError(t, c.ValidateEID("89049032123451234512345678901235"))
}

func createCert(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(parentKey.Curve, rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		PolicyIdentifiers:     []stdasn1.ObjectIdentifier{{2, 23, 146, 1, 2, 1, 4}},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &leafKey.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
