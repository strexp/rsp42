package cert

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"rsp42/internal/kms"
)

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
func Load(opts Options, provider kms.SignerLoader) (*Manager, error) {
	return LoadSets([]Options{opts}, provider)
}

// LoadSets loads the primary identity plus any additional identities. Selecting
// the matching identity at runtime lets one deployment serve eUICCs whose
// proposed CI differs.
func LoadSets(optsList []Options, provider kms.SignerLoader) (*Manager, error) {
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
