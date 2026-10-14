package cert

import (
	"crypto/x509"
	"fmt"
)

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
