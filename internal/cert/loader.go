package cert

import (
	"crypto/x509"
	"fmt"
	"path/filepath"

	"rsp42/internal/kms"
)

func (m *Manager) loadIdentity(opts Options, provider kms.SignerLoader, primary bool) (*Identity, error) {
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
