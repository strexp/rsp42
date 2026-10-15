package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"rsp42/internal/asn1"
)

// Validate checks the configuration for the given role and returns an
// actionable error describing the first problem found.
func (c *Config) Validate(role Role) error {
	if err := c.validateCommon(); err != nil {
		return err
	}
	switch role {
	case RoleDP:
		return c.validateDP()
	case RoleDS:
		return c.validateDS()
	case RoleAdminStore:
		return c.validateStore()
	case RolePreflight:
		if err := c.validateDP(); err != nil {
			return fmt.Errorf("sm-dp+ config: %w", err)
		}
		if err := c.validateDS(); err != nil {
			return fmt.Errorf("sm-ds config: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown validation role %d", role)
	}
}

func (c *Config) validateCommon() error {
	if err := c.Log.Validate(); err != nil {
		return err
	}
	if err := c.KMS.Validate(); err != nil {
		return err
	}
	// A sink the logger does not recognise used to build a no-op logger, so the
	// audit trail went away without a word. Fail at startup instead.
	if c.Audit.Enabled {
		if err := c.Audit.Validate(); err != nil {
			return err
		}
	}
	if err := validateCORS(c.SMDpp.Server.CORS); err != nil {
		return fmt.Errorf("smdpp.server.cors: %w", err)
	}
	if err := validateCORS(c.SMDS.Server.CORS); err != nil {
		return fmt.Errorf("smds.server.cors: %w", err)
	}
	return nil
}

// validateStore is the validation profile of the database-only admin commands
// (RoleAdminStore). It keeps the checks that protect shared invariants — the
// SQLite-only decision (docs/esim42-integration-gaps.md §8.4 decision 7) and the
// SAIP version list the template importer relies on — and skips everything that
// is only meaningful to a running server.
func (c *Config) validateStore() error {
	if err := c.Log.Validate(); err != nil {
		return err
	}
	if err := c.Profiles.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Profiles.Store.DSN) == "" {
		return fmt.Errorf("profiles.store.dsn is required")
	}
	if strings.TrimSpace(c.SMDS.Store.DSN) == "" {
		return fmt.Errorf("smds.store.dsn is required")
	}
	return nil
}

// ValidateCORS rejects empty origin entries.
func validateCORS(c CORSConfig) error {
	for i, o := range c.AllowedOrigins {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("allowed_origins[%d] must not be empty", i)
		}
	}
	return nil
}

func (c *Config) validateDP() error {
	s := &c.SMDpp
	if !s.Enabled {
		return nil
	}
	if s.FQDN == "" {
		return fmt.Errorf("smdpp.fqdn is required")
	}
	if s.OID == "" {
		return fmt.Errorf("smdpp.oid is required")
	}
	if err := validateOID(s.OID); err != nil {
		return fmt.Errorf("smdpp.oid: %w", err)
	}
	if !validCurve(s.Curve) {
		return fmt.Errorf("smdpp.curve %q invalid (want nist|brainpool)", s.Curve)
	}
	if len(s.HostID)%2 != 0 {
		return fmt.Errorf("smdpp.host_id must be an even-length hex string")
	}
	if _, err := hex.DecodeString(s.HostID); err != nil {
		return fmt.Errorf("smdpp.host_id: %w", err)
	}
	if s.TransactionIDLen < 1 || s.TransactionIDLen > 32 {
		return fmt.Errorf("smdpp.transaction_id_len %d out of range [1,32]", s.TransactionIDLen)
	}
	if s.SessionTTL <= 0 {
		return fmt.Errorf("smdpp.session_ttl must be positive")
	}
	if s.DownloadTTL <= 0 {
		return fmt.Errorf("smdpp.download_ttl must be positive")
	}
	if s.MaxDownloadAttempts < 1 {
		return fmt.Errorf("smdpp.max_download_attempts must be >= 1")
	}
	if s.MaxCCAttempts < 1 {
		return fmt.Errorf("smdpp.max_cc_attempts must be >= 1")
	}

	r := &c.Certs
	if !dirExists(r.RootDir) {
		return fmt.Errorf("certs.root_dir %q does not exist", r.RootDir)
	}
	curveTag := curveSuffix(s.Curve)
	for _, p := range []struct{ name, path string }{
		{"dp_auth cert", filepath.Join(r.RootDir, r.DPAuth, "CERT_DPauth_"+curveTag+".der")},
		{"dp_pb cert", filepath.Join(r.RootDir, r.DPPb, "CERT_DPpb_"+curveTag+".der")},
		{"ci cert", filepath.Join(r.RootDir, r.CI, "CERT_CI_"+curveTag+".der")},
		{"eum cert", filepath.Join(r.RootDir, r.EUM, "CERT_EUM_"+curveTag+".der")},
		{"euicc cert", filepath.Join(r.RootDir, r.EUICC, "CERT_EUICC_"+curveTag+".der")},
	} {
		if !fileExists(p.path) {
			return fmt.Errorf("certs: %s not found at %s", p.name, p.path)
		}
	}
	for i, extra := range r.Identities {
		if !dirExists(extra.RootDir) {
			return fmt.Errorf("certs.identities[%d].root_dir %q does not exist", i, extra.RootDir)
		}
		if extra.CI == "" {
			return fmt.Errorf("certs.identities[%d].ci is required", i)
		}
		ci := filepath.Join(extra.RootDir, extra.CI, "CERT_CI_"+curveTag+".der")
		if !fileExists(ci) {
			return fmt.Errorf("certs.identities[%d]: CI cert not found at %s", i, ci)
		}
	}
	if err := c.Profiles.Validate(); err != nil {
		return err
	}
	for i, m := range s.ES2P.RequesterTenants {
		if strings.TrimSpace(m.Requester) == "" {
			return fmt.Errorf("smdpp.es2p.requester_tenants[%d].requester must not be empty", i)
		}
	}
	if err := validateKEKConfig(&c.KMS); err != nil {
		return err
	}
	cb := c.Notifications.ES2PCallback
	if cb.Enabled {
		if cb.URL == "" {
			return fmt.Errorf("notifications.es2p_callback.url is required when enabled")
		}
		if cb.MaxAttempts < 1 {
			return fmt.Errorf("notifications.es2p_callback.max_attempts must be >= 1")
		}
		if cb.RetryInterval <= 0 {
			return fmt.Errorf("notifications.es2p_callback.retry_interval must be positive")
		}
	}
	// The ACR confirmation (ES2+.HandleAcrRequest) is configured independently
	// of the progress callbacks, so it is validated on its own.
	if cb.ACRURL != "" {
		u, err := url.Parse(cb.ACRURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("notifications.es2p_callback.acr_url %q is not a valid absolute URL", cb.ACRURL)
		}
	}
	if cb.ACRTimeout < 0 {
		return fmt.Errorf("notifications.es2p_callback.acr_timeout must be >= 0")
	}
	if (cb.ClientCertFile == "") != (cb.ClientKeyFile == "") {
		return fmt.Errorf("notifications.es2p_callback.client_cert_file and client_key_file must be set together")
	}
	if cb.ClientCertFile != "" || cb.CAFile != "" {
		for _, p := range []struct{ name, path string }{
			{"client_cert_file", cb.ClientCertFile},
			{"client_key_file", cb.ClientKeyFile},
			{"ca_file", cb.CAFile},
		} {
			if p.path != "" && !fileExists(p.path) {
				return fmt.Errorf("notifications.es2p_callback: %s not found at %s", p.name, p.path)
			}
		}
	}
	if s.ES12.Enabled {
		if s.ES12.SMDSAddress == "" {
			return fmt.Errorf("smdpp.es12.smds_address is required when es12 is enabled")
		}
		if !fileExists(s.ES12.TLS.ClientCertFile) {
			return fmt.Errorf("smdpp.es12.tls.client_cert_file not found at %s", s.ES12.TLS.ClientCertFile)
		}
		if !fileExists(s.ES12.TLS.ClientKeyFile) {
			return fmt.Errorf("smdpp.es12.tls.client_key_file not found at %s", s.ES12.TLS.ClientKeyFile)
		}
		if !fileExists(s.ES12.TLS.CAFile) {
			return fmt.Errorf("smdpp.es12.tls.ca_file not found at %s", s.ES12.TLS.CAFile)
		}
	}
	return nil
}

func (c *Config) validateDS() error {
	s := &c.SMDS
	if !s.Enabled {
		return nil
	}
	switch s.Role {
	case "root", "alternative":
	default:
		return fmt.Errorf("smds.role %q invalid (want root|alternative)", s.Role)
	}
	if s.FQDN == "" {
		return fmt.Errorf("smds.fqdn is required")
	}
	if s.OID == "" {
		return fmt.Errorf("smds.oid is required")
	}
	if err := validateOID(s.OID); err != nil {
		return fmt.Errorf("smds.oid: %w", err)
	}
	if !validCurve(s.Curve) {
		return fmt.Errorf("smds.curve %q invalid (want nist|brainpool)", s.Curve)
	}
	if s.EventTTL < 0 {
		return fmt.Errorf("smds.event_ttl must be >= 0")
	}
	if s.SessionTTL <= 0 {
		return fmt.Errorf("smds.session_ttl must be positive")
	}
	if s.Role == "alternative" {
		if !s.Cascade.Enabled {
			return fmt.Errorf("smds.cascade.enabled must be true when role=alternative")
		}
		if s.Cascade.RootAddress == "" {
			return fmt.Errorf("smds.cascade.root_address is required when role=alternative")
		}
	}
	if s.Cascade.Enabled {
		if s.Cascade.RootAddress == "" {
			return fmt.Errorf("smds.cascade.root_address is required when cascade is enabled")
		}
		if s.Cascade.RootAddress == s.FQDN {
			return fmt.Errorf("smds.cascade.root_address must differ from smds.fqdn")
		}
	}
	curveTag := curveSuffix(s.Curve)
	for _, p := range []struct{ name, path string }{
		{"dsauth cert", s.DSAuth.CertFile},
		{"dsauth key", s.DSAuth.KeyFile},
		{"dstls cert", s.DSTLS.CertFile},
		{"dstls key", s.DSTLS.KeyFile},
		{"ci cert", filepath.Join(c.Certs.RootDir, c.Certs.CI, "CERT_CI_"+curveTag+".der")},
	} {
		if !fileExists(p.path) {
			return fmt.Errorf("certs: %s not found at %s", p.name, p.path)
		}
	}
	return nil
}

func validCurve(s string) bool {
	switch s {
	case "nist", "brainpool":
		return true
	}
	return false
}

// curveSuffix maps a config curve name to the SGP.26 filename suffix.
func curveSuffix(s string) string {
	switch s {
	case "brainpool":
		return "BRP"
	default:
		return "NIST"
	}
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// validateOID checks that s is a valid dotted OBJECT IDENTIFIER. It delegates
// to asn1.EncodeOID so that configuration validation and DER encoding share one
// rule: anything that passes here is guaranteed to encode without error.
func validateOID(s string) error {
	if _, err := asn1.EncodeOID(s); err != nil {
		return err
	}
	return nil
}

func validateKEK(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("kms.kek_file: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("kms.kek_file %q must be exactly 32 bytes, got %d", path, len(b))
	}
	return nil
}

func validateKEKConfig(k *KMSConfig) error {
	switch {
	case k.KEKHex != "":
		b, err := hex.DecodeString(strings.TrimSpace(k.KEKHex))
		if err != nil {
			return fmt.Errorf("kms.kek_hex: %w", err)
		}
		if len(b) != 32 {
			return fmt.Errorf("kms.kek_hex must be 64 hex characters (32 bytes), got %d bytes", len(b))
		}
		return nil
	case k.KEKFile != "":
		return validateKEK(k.KEKFile)
	default:
		return fmt.Errorf("kms.kek_hex or kms.kek_file is required")
	}
}
