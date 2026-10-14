package service

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"rsp42/internal/cert"
)

// ecdsaKey asserts that a crypto.Signer is an ECDSA private key.
func ecdsaKey(s crypto.Signer) (*ecdsa.PrivateKey, error) {
	k, ok := s.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("service: key is not ECDSA")
	}
	return k, nil
}

// parseCertificates parses a list of DER certificates, returning an error if any
// entry is not a valid certificate.
func parseCertificates(ders [][]byte) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// eidFromCert extracts the EID from the eUICC certificate's subject
// serialNumber attribute.
func eidFromCert(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.String() == "2.5.4.5" { // serialNumber
			if s, ok := n.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// validateEUICCChain verifies CERT.EUICC against CERT.EUM, any intermediate
// certificates (otherCertsInChain) and the selected CI. When intermediates are
// absent the EUM must be directly signed by the session's CI key id.
func validateEUICCChain(euicc, eum *x509.Certificate, intermediates []*x509.Certificate, ci *x509.Certificate, ciCertID []byte) error {
	if ci == nil {
		return fmt.Errorf("no CI loaded")
	}
	if len(intermediates) == 0 && len(ciCertID) > 0 && !bytes.Equal(eum.AuthorityKeyId, ciCertID) {
		return fmt.Errorf("EUM AKI does not match selected CI key id")
	}
	chain := make([]*x509.Certificate, 0, 2+len(intermediates))
	chain = append(chain, eum)
	chain = append(chain, intermediates...)
	chain = append(chain, ci)
	if err := cert.VerifySignatureChain(euicc, chain); err != nil {
		return err
	}
	return nil
}
