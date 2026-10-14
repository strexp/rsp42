package cert

import (
	"bytes"
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

// Identity is one certificate set: a CI/EUM trust anchor together with the
// SM-DP+ (and optionally SM-DS) signing material issued by that CI. A Manager
// may hold several identities so a single deployment can serve eUICCs that
// propose different CI key identifiers (SGP.26 certificate variants).
type Identity struct {
	CI  *x509.Certificate
	EUM *x509.Certificate

	DPAuthCert *x509.Certificate
	DPAuthKey  crypto.Signer
	DPPbCert   *x509.Certificate
	DPPbKey    crypto.Signer

	DSAuthCert *x509.Certificate
	DSAuthKey  crypto.Signer
}

// Manager holds the loaded and validated certificate material for both roles.
// The first identity is the primary one; its TLS certificates are the ones
// presented by the listeners.
type Manager struct {
	opts     Options
	now      time.Time
	warnings []string

	ids   []*Identity
	euicc *x509.Certificate

	dpTLSCert *x509.Certificate
	dpTLSKey  crypto.Signer
	dsTLSCert *x509.Certificate
	dsTLSKey  crypto.Signer
}

// Load reads and validates the configured certificate material (a single
// identity).
func Load(opts Options, provider kms.Provider) (*Manager, error) {
	return LoadSets([]Options{opts}, provider)
}

// LoadSets loads the primary identity plus any additional identities. Selecting
// the matching identity at runtime lets one deployment serve eUICCs whose
// proposed CI differs.
func LoadSets(optsList []Options, provider kms.Provider) (*Manager, error) {
	if len(optsList) == 0 {
		return nil, fmt.Errorf("cert: no certificate configuration")
	}
	m := &Manager{opts: optsList[0], now: time.Now()}
	for i, opts := range optsList {
		id, err := m.loadIdentity(opts, provider, i == 0)
		if err != nil {
			return nil, err
		}
		m.ids = append(m.ids, id)
	}
	return m, nil
}

func (m *Manager) loadIdentity(opts Options, provider kms.Provider, primary bool) (*Identity, error) {
	id := &Identity{}

	ci, err := m.loadCert(opts, opts.CI, "CERT_CI")
	if err != nil {
		return nil, err
	}
	if err := m.validateCI(ci); err != nil {
		return nil, err
	}
	id.CI = ci

	if eum, err := m.loadCertOptional(opts, opts.EUM, "CERT_EUM"); err != nil {
		return nil, err
	} else if eum != nil {
		if err := m.validateEUM(eum, ci); err != nil {
			return nil, err
		}
		id.EUM = eum
	}

	if opts.EUICC != "" {
		euicc, err := m.loadCertOptional(opts, opts.EUICC, "CERT_EUICC")
		if err != nil {
			return nil, err
		}
		if euicc != nil {
			if err := m.validateEUICC(euicc, id.EUM); err != nil {
				return nil, err
			}
			if primary {
				m.euicc = euicc
			}
		}
	}

	if opts.DPAuth != "" {
		c, err := m.loadCert(opts, opts.DPAuth, "CERT_DPauth")
		if err != nil {
			return nil, err
		}
		k, err := provider.LoadSigner(filepath.Join(opts.RootDir, opts.DPAuth, "SK_DPauth_"+opts.curve()+".pem"))
		if err != nil {
			return nil, err
		}
		if err := m.validateDPAuth(c, opts, ci); err != nil {
			return nil, err
		}
		id.DPAuthCert, id.DPAuthKey = c, k
	}
	if opts.DPPb != "" {
		c, err := m.loadCert(opts, opts.DPPb, "CERT_DPpb")
		if err != nil {
			return nil, err
		}
		k, err := provider.LoadSigner(filepath.Join(opts.RootDir, opts.DPPb, "SK_DPpb_"+opts.curve()+".pem"))
		if err != nil {
			return nil, err
		}
		if err := m.validateDPPb(c, opts, ci); err != nil {
			return nil, err
		}
		id.DPPbCert, id.DPPbKey = c, k
	}
	if opts.DSAuth != "" {
		c, err := m.loadCert(opts, opts.DSAuth, "CERT_DSauth")
		if err != nil {
			return nil, err
		}
		k, err := provider.LoadSigner(filepath.Join(opts.RootDir, opts.DSAuth, "SK_DSauth_"+opts.curve()+".pem"))
		if err != nil {
			return nil, err
		}
		if err := m.validateDSAuth(c, opts, ci); err != nil {
			return nil, err
		}
		id.DSAuthCert, id.DSAuthKey = c, k
	}

	if primary {
		if opts.DPTLS != "" {
			c, err := m.loadCert(opts, opts.DPTLS, "CERT_DPtls")
			if err != nil {
				return nil, err
			}
			k, err := provider.LoadSigner(filepath.Join(opts.RootDir, opts.DPTLS, "SK_DPtls_"+opts.curve()+".pem"))
			if err != nil {
				return nil, err
			}
			if err := m.validateDPTLS(c, opts, ci); err != nil {
				return nil, err
			}
			m.dpTLSCert, m.dpTLSKey = c, k
		}
		if opts.DSTLS != "" {
			c, err := m.loadCert(opts, opts.DSTLS, "CERT_DStls")
			if err != nil {
				return nil, err
			}
			k, err := provider.LoadSigner(filepath.Join(opts.RootDir, opts.DSTLS, "SK_DStls_"+opts.curve()+".pem"))
			if err != nil {
				return nil, err
			}
			if err := m.validateDSTLS(c, opts, ci); err != nil {
				return nil, err
			}
			m.dsTLSCert, m.dsTLSKey = c, k
		}
	}
	return id, nil
}

func (m *Manager) loadCert(opts Options, dir, base string) (*x509.Certificate, error) {
	c, err := m.loadCertOptional(opts, dir, base)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("cert: %s not configured", base)
	}
	return c, nil
}

func (m *Manager) loadCertOptional(opts Options, dir, base string) (*x509.Certificate, error) {
	if dir == "" {
		return nil, nil
	}
	path := filepath.Join(opts.RootDir, dir, base+"_"+opts.curve()+".der")
	c, err := LoadCertificate(path)
	if err != nil {
		// Fall back to PEM.
		c, err = LoadCertificate(filepath.Join(opts.RootDir, dir, base+"_"+opts.curve()+".pem"))
		if err != nil {
			return nil, err
		}
	}
	if err := CheckValidity(c, m.now, opts.AllowExpired); err != nil {
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

func (m *Manager) validateEUM(c, ci *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleEUM); err != nil {
		return err
	}
	if !c.IsCA || c.MaxPathLen != 0 {
		return &ValidationError{Cert: "EUM", Reason: "must be a CA with pathLen 0"}
	}
	if c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &ValidationError{Cert: "EUM", Reason: "missing keyCertSign"}
	}
	return m.verifyFrom(c, ci)
}

func (m *Manager) validateEUICC(c, eum *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleEUICC); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "eUICC", Reason: "missing digitalSignature"}
	}
	return m.verifyFrom(c, eum)
}

func (m *Manager) validateDPAuth(c *x509.Certificate, opts Options, ci *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDPAuth); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "DPauth", Reason: "missing digitalSignature"}
	}
	if err := m.requireRID(c, opts.DPOID); err != nil {
		return err
	}
	return m.verifyFrom(c, ci)
}

func (m *Manager) validateDPPb(c *x509.Certificate, opts Options, ci *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDPPb); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "DPpb", Reason: "missing digitalSignature"}
	}
	if err := m.requireRID(c, opts.DPOID); err != nil {
		return err
	}
	return m.verifyFrom(c, ci)
}

func (m *Manager) validateDPTLS(c *x509.Certificate, opts Options, ci *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDPTLS); err != nil {
		return err
	}
	if err := m.requireEKU(c, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth); err != nil {
		return err
	}
	if err := m.requireRID(c, opts.DPOID); err != nil {
		return err
	}
	if err := m.requireDNS(c, opts.DPFQDN); err != nil {
		return err
	}
	return m.verifyFrom(c, ci)
}

func (m *Manager) validateDSAuth(c *x509.Certificate, opts Options, ci *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDSAuth); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return &ValidationError{Cert: "DSauth", Reason: "missing digitalSignature"}
	}
	if err := m.requireRID(c, opts.DSOID); err != nil {
		return err
	}
	return m.verifyFrom(c, ci)
}

func (m *Manager) validateDSTLS(c *x509.Certificate, opts Options, ci *x509.Certificate) error {
	if err := RequireRole(c, OIDRoleDSTLS); err != nil {
		return err
	}
	if err := m.requireEKU(c, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth); err != nil {
		return err
	}
	if err := m.requireRID(c, opts.DSOID); err != nil {
		return err
	}
	if err := m.requireDNS(c, opts.DSFQDN); err != nil {
		return err
	}
	return m.verifyFrom(c, ci)
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

// Curve returns the configured curve name of the primary identity.
func (m *Manager) Curve() string { return m.opts.Curve }

// Count returns the number of loaded identities.
func (m *Manager) Count() int { return len(m.ids) }

// Identities returns all loaded identities (the first is the primary one).
func (m *Manager) Identities() []*Identity { return m.ids }

// CI returns the primary certificate issuer.
func (m *Manager) CI() *x509.Certificate { return m.ids[0].CI }

// EUM returns the primary EUM certificate.
func (m *Manager) EUM() *x509.Certificate { return m.ids[0].EUM }

// EUICC returns the test eUICC certificate of the primary identity.
func (m *Manager) EUICC() *x509.Certificate { return m.euicc }

// DPAuth returns the primary DP authentication certificate.
func (m *Manager) DPAuth() *x509.Certificate { return m.ids[0].DPAuthCert }

// DPAuthKey returns the primary DP authentication signing key.
func (m *Manager) DPAuthKey() crypto.Signer { return m.ids[0].DPAuthKey }

// DPPb returns the primary DP profile-binding certificate.
func (m *Manager) DPPb() *x509.Certificate { return m.ids[0].DPPbCert }

// DPPbKey returns the primary DP profile-binding signing key.
func (m *Manager) DPPbKey() crypto.Signer { return m.ids[0].DPPbKey }

// DSAuth returns the primary DS authentication certificate.
func (m *Manager) DSAuth() *x509.Certificate { return m.ids[0].DSAuthCert }

// DSAuthKey returns the primary DS authentication signing key.
func (m *Manager) DSAuthKey() crypto.Signer { return m.ids[0].DSAuthKey }

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

// SelectIdentity chooses the identity whose CI key identifier appears in the
// eUICC's proposed euiccCiPKIdToBeUsed list.
func (m *Manager) SelectIdentity(proposed [][]byte) (*Identity, error) {
	for _, p := range proposed {
		ski := p
		// euiccCiPKIdToBeUsed entries are commonly 04 || 20-byte SKI or just
		// the raw SKI; strip a leading uncompressed-point marker if present.
		if len(ski) == 21 && ski[0] == 0x04 {
			ski = ski[1:]
		}
		for _, id := range m.ids {
			if id.CI != nil && hex.EncodeToString(ski) == hex.EncodeToString(id.CI.SubjectKeyId) {
				return id, nil
			}
		}
	}
	return nil, fmt.Errorf("cert: none of the eUICC-proposed CI key IDs match a loaded CI")
}

// IdentityByCIKeyID finds the identity whose CI has the given SubjectKeyIdentifier.
func (m *Manager) IdentityByCIKeyID(ski []byte) *Identity {
	for _, id := range m.ids {
		if id.CI != nil && bytes.Equal(id.CI.SubjectKeyId, ski) {
			return id
		}
	}
	return nil
}

// CIByAKI finds the CI whose SubjectKeyIdentifier matches an issuer's
// AuthorityKeyIdentifier (used when validating notifications that carry their
// own EUM certificate).
func (m *Manager) CIByAKI(aki []byte) *x509.Certificate {
	if len(aki) == 0 {
		return nil
	}
	for _, id := range m.ids {
		if id.CI != nil && bytes.Equal(id.CI.SubjectKeyId, aki) {
			return id.CI
		}
	}
	return nil
}

// SelectCI chooses the CI whose SKI appears in the eUICC's proposed
// euiccCiPKIdToBeUsed list (each entry is 0x04||X||Y or a 20-byte SKI).
func (m *Manager) SelectCI(proposed [][]byte) (*x509.Certificate, error) {
	id, err := m.SelectIdentity(proposed)
	if err != nil {
		return nil, err
	}
	return id.CI, nil
}
