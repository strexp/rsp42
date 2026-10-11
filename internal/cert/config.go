package cert

import "rsp42/internal/config"

// OptionsFromConfig builds certificate load options from the application
// configuration.
func OptionsFromConfig(c *config.Config) Options {
	return Options{
		RootDir:      c.Certs.RootDir,
		CI:           c.Certs.CI,
		EUM:          c.Certs.EUM,
		EUICC:        c.Certs.EUICC,
		DPAuth:       c.Certs.DPAuth,
		DPPb:         c.Certs.DPPb,
		DPTLS:        c.Certs.DPTLS,
		DSAuth:       c.Certs.DSAuth,
		DSTLS:        c.Certs.DSTLS,
		Curve:        c.SMDpp.Curve,
		DPFQDN:       c.SMDpp.FQDN,
		DPOID:        c.SMDpp.OID,
		DSFQDN:       c.SMDS.FQDN,
		DSOID:        c.SMDS.OID,
		AllowExpired: c.Certs.AllowExpiredTestCerts,
	}
}
