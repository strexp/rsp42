package cert

import "rsp42/internal/config"

// OptionsFromConfig builds certificate load options from the application
// configuration (the primary identity).
func OptionsFromConfig(c *config.Config) Options {
	return optionsFromCerts(c, c.Certs)
}

// OptionsListFromConfig returns the primary identity followed by any additional
// configured identities.
func OptionsListFromConfig(c *config.Config) []Options {
	out := []Options{optionsFromCerts(c, c.Certs)}
	for _, extra := range c.Certs.Identities {
		out = append(out, optionsFromCerts(c, extra))
	}
	return out
}

func optionsFromCerts(c *config.Config, cc config.CertsConfig) Options {
	return Options{
		RootDir:      cc.RootDir,
		CI:           cc.CI,
		EUM:          cc.EUM,
		EUICC:        cc.EUICC,
		DPAuth:       cc.DPAuth,
		DPPb:         cc.DPPb,
		DPTLS:        cc.DPTLS,
		DSAuth:       cc.DSAuth,
		DSTLS:        cc.DSTLS,
		Curve:        c.SMDpp.Curve,
		DPFQDN:       c.SMDpp.FQDN,
		DPOID:        c.SMDpp.OID,
		DSFQDN:       c.SMDS.FQDN,
		DSOID:        c.SMDS.OID,
		AllowExpired: cc.AllowExpiredTestCerts,
	}
}
