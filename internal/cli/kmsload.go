package cli

import (
	"log/slog"

	"rsp42/internal/cert"
	"rsp42/internal/config"
	"rsp42/internal/kms"
)

// loadCertificates builds the KMS provider and validates the configured
// certificate material at startup.
func loadCertificates(cfg *config.Config, log *slog.Logger) (*cert.Manager, *kms.FileProvider, error) {
	provider, err := kms.OpenFileProvider(cfg.KMS.KEKHex, cfg.KMS.KEKFile)
	if err != nil {
		return nil, nil, err
	}
	m, err := cert.LoadSets(certOptionsList(cfg), provider)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range m.Warnings() {
		log.Warn("certificate", "detail", w)
	}
	return m, provider, nil
}

// certOptionsList returns the primary certificate identity followed by any
// additional configured identities.
//
// The mapping from the application configuration to cert.Options lives in the
// composition root on purpose: cert is a primitive below the configuration
// layer, so it must not import internal/config (internal/archcheck pins that).
func certOptionsList(cfg *config.Config) []cert.Options {
	out := []cert.Options{certOptions(cfg, cfg.Certs)}
	for _, extra := range cfg.Certs.Identities {
		out = append(out, certOptions(cfg, extra))
	}
	return out
}

// certOptions maps one configured identity to the cert package's load options.
func certOptions(cfg *config.Config, cc config.CertsConfig) cert.Options {
	return cert.Options{
		RootDir:      cc.RootDir,
		CI:           cc.CI,
		EUM:          cc.EUM,
		EUICC:        cc.EUICC,
		DPAuth:       cc.DPAuth,
		DPPb:         cc.DPPb,
		DPTLS:        cc.DPTLS,
		DSAuth:       cc.DSAuth,
		DSTLS:        cc.DSTLS,
		Curve:        cfg.SMDpp.Curve,
		DPFQDN:       cfg.SMDpp.FQDN,
		DPOID:        cfg.SMDpp.OID,
		DSFQDN:       cfg.SMDS.FQDN,
		DSOID:        cfg.SMDS.OID,
		AllowExpired: cc.AllowExpiredTestCerts,
	}
}
