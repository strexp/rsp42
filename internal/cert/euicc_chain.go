package cert

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

// ParseCertificates parses a list of DER certificates, returning an error if any
// entry is not a valid certificate.
func ParseCertificates(ders [][]byte) ([]*x509.Certificate, error) {
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

// EIDFromCert extracts the EID from the eUICC certificate's subject
// serialNumber attribute (2.5.4.5).
func EIDFromCert(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.String() == "2.5.4.5" { // serialNumber
			if s, ok := n.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

// ValidateEUICCChain verifies CERT.EUICC against CERT.EUM, any intermediate
// certificates (otherCertsInChain) and the selected CI. When intermediates are
// absent the EUM must be directly signed by the session's CI key id.
func ValidateEUICCChain(euicc, eum *x509.Certificate, intermediates []*x509.Certificate, ci *x509.Certificate, ciCertID []byte) error {
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
	if err := VerifySignatureChain(euicc, chain); err != nil {
		return err
	}
	return nil
}
