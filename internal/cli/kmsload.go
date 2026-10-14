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
	provider, err := newKMSProvider(&cfg.KMS)
	if err != nil {
		return nil, nil, err
	}
	m, err := cert.LoadSets(cert.OptionsListFromConfig(cfg), provider)
	if err != nil {
		return nil, nil, err
	}
	for _, w := range m.Warnings() {
		log.Warn("certificate", "detail", w)
	}
	return m, provider, nil
}

// newKMSProvider builds the software KMS from the configured key source
// (kek_hex preferred, else kek_file).
func newKMSProvider(cfg *config.KMSConfig) (*kms.FileProvider, error) {
	if cfg.KEKHex != "" {
		return kms.NewFileProviderFromHex(cfg.KEKHex)
	}
	return kms.NewFileProvider(cfg.KEKFile)
}
