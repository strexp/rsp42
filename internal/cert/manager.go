package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"rsp42/internal/kms"
)

// Options describes where the certificate material lives.
type Options struct {
	RootDir      string
	CI           string
	EUM          string
	EUICC        string
	DPAuth       string
	DPPb         string
	DPTLS        string
	DSAuth       string
	DSTLS        string
	Curve        string // "nist" | "brainpool"
	DPFQDN       string
	DPOID        string
	DSFQDN       string
	DSOID        string
	AllowExpired bool
}

func (o Options) curve() string {
	if o.Curve == "brainpool" {
		return "BRP"
	}
	return "NIST"
}

// Manager holds the loaded and validated certificate material for both roles.
type Manager struct {
	opts     Options
	now      time.Time
	warnings []string

	ci    *x509.Certificate
	eum   *x509.Certificate
	euicc *x509.Certificate

	dpAuthCert *x509.Certificate
	dpAuthKey  crypto.Signer
	dpPbCert   *x509.Certificate
	dpPbKey    crypto.Signer
	dpTLSCert  *x509.Certificate
	dpTLSKey   crypto.Signer

	dsAuthCert *x509.Certificate
	dsAuthKey  crypto.Signer
	dsTLSCert  *x509.Certificate
	dsTLSKey   crypto.Signer
}

// Load reads and validates the configured certificate material.
func Load(opts Options, provider kms.Provider) (*Manager, error) {
	m := &Manager{opts: opts, now: time.Now()}
	var err error

	if m.ci, err = m.loadCert(opts.CI, "CERT_CI"); err != nil {
		return nil, err
	}
	if err := m.validateCI(m.ci); err != nil {
		return nil, err
	}
	if m.eum, err = m.loadCert(opts.EUM, "CERT_EUM"); err != nil {
		return nil, err
	}
	if err := m.validateEUM(m.eum); err != nil {
		return nil, err
	}
	if m.euicc, err = m.loadCert(opts.EUICC, "CERT_EUICC"); err != nil {
		return nil, err
	}
	if err := m.validateEUICC(m.euicc); err != nil {
		return nil, err
	}

	if m.dpAuthCert, err = m.loadCert(opts.DPAuth, "CERT_DPauth"); err != nil {
		return nil, err
	}
	if m.dpAuthKey, err = provider.LoadSigner(filepath.Join(opts.RootDir, opts.DPAuth, "SK_DPauth_"+opts.curve()+".pem")); err != nil {
		return nil, err
	}
	if err := m.validateDPAuth(m.dpAuthCert); err != nil {
		return nil, err
	}
	if m.dpPbCert, err = m.loadCert(opts.DPPb, "CERT_DPpb"); err != nil {
		return nil, err
	}
	if m.dpPbKey, err = provider.LoadSigner(filepath.Join(opts.RootDir, opts.DPPb, "SK_DPpb_"+opts.curve()+".pem")); err != nil {
		return nil, err
	}
	if err := m.validateDPPb(m.dpPbCert); err != nil {
		return nil, err
	}
	if m.dpTLSCert, err = m.loadCert(opts.DPTLS, "CERT_DPtls"); err != nil {
		return nil, err
	}
	if m.dpTLSCert != nil {
		if m.dpTLSKey, err = provider.LoadSigner(filepath.Join(opts.RootDir, opts.DPTLS, "SK_DPtls_"+opts.curve()+".pem")); err != nil {
			return nil, err
		}
		if err := m.validateDPTLS(m.dpTLSCert); err != nil {
			return nil, err
		}
	}

	if m.dsAuthCert, err = m.loadCert(opts.DSAuth, "CERT_DSauth"); err != nil {
		return nil, err
	}
	if m.dsAuthCert != nil {
		if m.dsAuthKey, err = provider.LoadSigner(filepath.Join(opts.RootDir, opts.DSAuth, "SK_DSauth_"+opts.curve()+".pem")); err != nil {
			return nil, err
		}
		if err := m.validateDSAuth(m.dsAuthCert); err != nil {
			return nil, err
		}
	}
	if m.dsTLSCert, err = m.loadCert(opts.DSTLS, "CERT_DStls"); err != nil {
		return nil, err
	}
	if m.dsTLSCert != nil {
		if m.dsTLSKey, err = provider.LoadSigner(filepath.Join(opts.RootDir, opts.DSTLS, "SK_DStls_"+opts.curve()+".pem")); err != nil {
			return nil, err
		}
		if err := m.validateDSTLS(m.dsTLSCert); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) loadCert(dir, base string) (*x509.Certificate, error) {
	if dir == "" {
		return nil, nil
	}
	path := filepath.Join(m.opts.RootDir, dir, base+"_"+m.opts.curve()+".der")
	c, err := LoadCertificate(path)
	if err != nil {
		// Fall back to PEM.
		c, err = LoadCertificate(filepath.Join(m.opts.RootDir, dir, base+"_"+m.opts.curve()+".pem"))
		if err != nil {
			return nil, err
		}
	}
	if err := CheckValidity(c, m.now, m.opts.AllowExpired); err != nil {
		return nil, err
	}
	if m.now.After(c.NotAfter) {
		m.warnings = append(m.warnings, fmt.Sprintf("%s is expired (accepted for test data)", path))
	}
	return c, nil
}

func (m *Manager) validateCI(c *x509.Certificate) error {
	if !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &ValidationError{Cert: "CI", Reason: "must be a CA with keyCertSign"}
	}
	if err := RequireRole(c, OIDRoleCI); err != nil {
		return err
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return &ValidationError{Cert: "CI", Reason: "not self-signed: " + err.Error()}
	}
	return nil
}

func (m *Manager) validateEUM(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleEUM); err != nil {
		return err
	}
	if !c.IsCA || c.MaxPathLen != 0 {
		return &ValidationError{Cert: "EUM", Reason: "must be a CA with pathLen 0"}
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &ValidationError{Cert: "EUM", Reason: "missing keyCertSign"}
	}
	return m.verifyFrom(c, m.ci)
}

func (m *Manager) validateEUICC(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleEUICC); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "eUICC", Reason: "missing digitalSignature"}
	}
	return m.verifyFrom(c, m.eum)
}

func (m *Manager) validateDPAuth(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDPAuth); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "DPauth", Reason: "missing digitalSignature"}
	}
	if err := m.requireRID(c, m.opts.DPOID); err != nil {
		return err
	}
	return m.verifyFrom(c, m.ci)
}

func (m *Manager) validateDPPb(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDPPb); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "DPpb", Reason: "missing digitalSignature"}
	}
	if err := m.requireRID(c, m.opts.DPOID); err != nil {
		return err
	}
	return m.verifyFrom(c, m.ci)
}

func (m *Manager) validateDPTLS(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDPTLS); err != nil {
		return err
	}
	if err := m.requireEKU(c, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth); err != nil {
		return err
	}
	if err := m.requireRID(c, m.opts.DPOID); err != nil {
		return err
	}
	if err := m.requireDNS(c, m.opts.DPFQDN); err != nil {
		return err
	}
	return m.verifyFrom(c, m.ci)
}

func (m *Manager) validateDSAuth(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDSAuth); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "DSauth", Reason: "missing digitalSignature"}
	}
	if err := m.requireRID(c, m.opts.DSOID); err != nil {
		return err
	}
	return m.verifyFrom(c, m.ci)
}

func (m *Manager) validateDSTLS(c *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDSTLS); err != nil {
		return err
	}
	if err := m.requireEKU(c, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth); err != nil {
		return err
	}
	if err := m.requireRID(c, m.opts.DSOID); err != nil {
		return err
	}
	if err := m.requireDNS(c, m.opts.DSFQDN); err != nil {
		return err
	}
	return m.verifyFrom(c, m.ci)
}

func (m *Manager) verifyFrom(leaf, issuer *x509.Certificate) error {
	if issuer == nil {
		return &ValidationError{Cert: leaf.Subject.String(), Reason: "missing issuer"}
	}
	return VerifySignatureChain(leaf, []*x509.Certificate{issuer})
}

func (m *Manager) requireRID(c *x509.Certificate, want string) error {
	if want == "" {
		return nil
	}
	ok, err := HasRegisteredID(c, want)
	if err != nil {
		return err
	}
	if !ok {
		return &ValidationError{Cert: c.Subject.String(), Reason: fmt.Sprintf("no SAN registered ID %s", want)}
	}
	return nil
}

func (m *Manager) requireDNS(c *x509.Certificate, want string) error {
	if want == "" {
		return nil
	}
	for _, d := range c.DNSNames {
		if d == want {
			return nil
		}
	}
	return &ValidationError{Cert: c.Subject.String(), Reason: fmt.Sprintf("SAN DNS does not contain %s", want)}
}

func (m *Manager) requireEKU(c *x509.Certificate, wanted ...x509.ExtKeyUsage) error {
	for _, w := range wanted {
		found := false
		for _, e := range c.ExtKeyUsage {
			if e == w {
				found = true
				break
			}
		}
		if !found {
			return &ValidationError{Cert: c.Subject.String(), Reason: fmt.Sprintf("missing extended key usage %v", w)}
		}
	}
	return nil
}

// Warnings returns non-fatal validation notes (e.g. expired test certificates).
func (m *Manager) Warnings() []string { return m.warnings }

// Curve returns the configured curve name.
func (m *Manager) Curve() string { return m.opts.Curve }

// CI returns the certificate issuer.
func (m *Manager) CI() *x509.Certificate { return m.ci }

// EUM returns the EUM certificate.
func (m *Manager) EUM() *x509.Certificate { return m.eum }

// EUICC returns the test eUICC certificate.
func (m *Manager) EUICC() *x509.Certificate { return m.euicc }

// DPAuth returns the DP authentication certificate.
func (m *Manager) DPAuth() *x509.Certificate { return m.dpAuthCert }

// DPAuthKey returns the DP authentication signing key.
func (m *Manager) DPAuthKey() crypto.Signer { return m.dpAuthKey }

// DPPb returns the DP profile-binding certificate.
func (m *Manager) DPPb() *x509.Certificate { return m.dpPbCert }

// DPPbKey returns the DP profile-binding signing key.
func (m *Manager) DPPbKey() crypto.Signer { return m.dpPbKey }

// DSAuth returns the DS authentication certificate.
func (m *Manager) DSAuth() *x509.Certificate { return m.dsAuthCert }

// DSAuthKey returns the DS authentication signing key.
func (m *Manager) DSAuthKey() crypto.Signer { return m.dsAuthKey }

// DPTLSCertificate returns the DP TLS certificate pair, if configured.
func (m *Manager) DPTLSCertificate() (*tls.Certificate, error) {
	return m.tlsPair(m.dpTLSCert, m.dpTLSKey)
}

// DSTLSCertificate returns the DS TLS certificate pair, if configured.
func (m *Manager) DSTLSCertificate() (*tls.Certificate, error) {
	return m.tlsPair(m.dsTLSCert, m.dsTLSKey)
}

func (m *Manager) tlsPair(c *x509.Certificate, k crypto.Signer) (*tls.Certificate, error) {
	if c == nil || k == nil {
		return nil, fmt.Errorf("cert: TLS certificate not configured")
	}
	return &tls.Certificate{Certificate: [][]byte{c.Raw}, PrivateKey: k, Leaf: c}, nil
}

// ECDSAKey returns the ECDSA key from a signer, if compatible.
func ECDSAKey(s crypto.Signer) (*ecdsa.PrivateKey, bool) {
	k, ok := s.(*ecdsa.PrivateKey)
	return k, ok
}

// SelectCI chooses the CI whose SKI appears in the eUICC's proposed
// euiccCiPKIdToBeUsed list (each entry is 0x04||X||Y or a 20-byte SKI).
func (m *Manager) SelectCI(proposed [][]byte) (*x509.Certificate, error) {
	if m.ci == nil {
		return nil, fmt.Errorf("cert: no CI loaded")
	}
	for _, p := range proposed {
		ski := p
		// euiccCiPKIdToBeUsed entries are commonly 04 || 20-byte SKI or just
		// the raw SKI; strip a leading uncompressed-point marker if present.
		if len(ski) == 21 && ski[0] == 0x04 {
			ski = ski[1:]
		}
		if hex.EncodeToString(ski) == hex.EncodeToString(m.ci.SubjectKeyId) {
			return m.ci, nil
		}
	}
	return nil, fmt.Errorf("cert: none of the eUICC-proposed CI key IDs match the loaded CI (SKI %X)", m.ci.SubjectKeyId)
}
