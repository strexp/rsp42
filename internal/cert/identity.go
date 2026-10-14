package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

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
