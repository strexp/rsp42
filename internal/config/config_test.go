package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const exampleConfig = "config/config.example.yaml"

// chdirRepo switches the working directory to the repository root so that the
// relative paths inside the example config resolve.
func chdirRepo(t *testing.T) {
	t.Helper()
	t.Chdir("../..")
}

func TestLoadExampleConfigForBothRoles(t *testing.T) {
	chdirRepo(t)
	cfg, err := Load(exampleConfig, RoleDP)
	require.NoError(t, err)
	require.Equal(t, "testsmdpplus1.example.com", cfg.SMDpp.FQDN)
	require.Equal(t, "nist", cfg.SMDpp.Curve)

	cfg, err = Load(exampleConfig, RoleDS)
	require.NoError(t, err)
	require.Equal(t, "root", cfg.SMDS.Role)
	require.Equal(t, "testrootsmds.example.com", cfg.SMDS.FQDN)
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), RoleDP)
	require.Error(t, err)
}

func TestEnvOverride(t *testing.T) {
	chdirRepo(t)
	t.Setenv("RSP42_SMDPP_FQDN", "override.example.com")
	cfg, err := Load(exampleConfig, RoleDP)
	require.NoError(t, err)
	require.Equal(t, "override.example.com", cfg.SMDpp.FQDN)
}

func TestValidateRejectsBadConfig(t *testing.T) {
	chdirRepo(t)
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"missing fqdn", func(c *Config) { c.SMDpp.FQDN = "" }},
		{"bad curve", func(c *Config) { c.SMDpp.Curve = "p384" }},
		{"bad host id", func(c *Config) { c.SMDpp.HostID = "xyz" }},
		{"bad log level", func(c *Config) { c.Log.Level = "verbose" }},
		{"ds alternative without cascade", func(c *Config) { c.SMDS.Role = "alternative" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(exampleConfig, RoleDP)
			require.NoError(t, err)
			tc.mut(cfg)
			require.Error(t, cfg.Validate(RolePreflight))
		})
	}
}

func TestValidateOID(t *testing.T) {
	require.NoError(t, validateOID("2.999.10"))
	require.NoError(t, validateOID("2.23.146.1.3.1.1"))
	require.NoError(t, validateOID("1.2.840.113549.1.1.11"))
	require.Error(t, validateOID("2..10"))
	require.Error(t, validateOID("2.abc"))
	require.Error(t, validateOID(""))
	// These used to pass validation and then panic in asn1.EncodeOID during
	// BPP generation (see docs/refactoring-plan.md 阶段 1.1).
	require.Error(t, validateOID("2"), "single arc must be rejected")
	require.Error(t, validateOID("9.1.2"), "first arc must be 0, 1 or 2")
	require.Error(t, validateOID("1.40.1"), "second arc must be <= 39 when the first arc is < 2")
	require.Error(t, validateOID("2.18446744073709551615"), "first two arcs must fit in uint64")
	require.Error(t, validateOID("1.2.99999999999999999999"), "arc must fit in uint64")
}

func TestKEKValidation(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "kek.bin")
	require.NoError(t, os.WriteFile(good, make([]byte, 32), 0o600))
	require.NoError(t, validateKEK(good))

	bad := filepath.Join(dir, "short.bin")
	require.NoError(t, os.WriteFile(bad, make([]byte, 16), 0o600))
	require.Error(t, validateKEK(bad))
}

// TestRepositoryIsSQLiteOnly pins decision 7 in docs/esim42-integration-gaps.md
// §8.4: no other storage backend is supported, and asking for one fails
// validation instead of being silently ignored.
func TestRepositoryIsSQLiteOnly(t *testing.T) {
	chdirRepo(t)
	load := func() *Config {
		t.Helper()
		cfg, err := Load(exampleConfig, RoleDP)
		require.NoError(t, err)
		return cfg
	}

	for _, backend := range []string{"postgres", "postgresql", "mysql", "memory", "SQLite"} {
		cfg := load()
		cfg.Profiles.Repository = backend
		err := cfg.Validate(RoleDP)
		require.Error(t, err, "backend %q must be rejected", backend)
		require.Contains(t, err.Error(), "profiles.repository")
	}

	cfg := load()
	cfg.Profiles.Repository = "sqlite"
	require.NoError(t, cfg.Validate(RoleDP))

	// An empty value is a misconfiguration, not "use the default".
	cfg = load()
	cfg.Profiles.Repository = ""
	err := cfg.Validate(RoleDP)
	require.Error(t, err)
	require.Contains(t, err.Error(), "profiles.repository")
}

// TestValidateACRConfig pins the G13 configuration contract: acr_url enables the
// Activation Code Retrieval confirmation independently of the progress
// callbacks, and a malformed ACR configuration fails fast.
func TestValidateACRConfig(t *testing.T) {
	chdirRepo(t)
	load := func() *Config {
		t.Helper()
		cfg, err := Load(exampleConfig, RoleDP)
		require.NoError(t, err)
		return cfg
	}

	// The G13 case: ACR configured while the progress callbacks stay disabled.
	cfg := load()
	require.False(t, cfg.Notifications.ES2PCallback.Enabled)
	require.Empty(t, cfg.Notifications.ES2PCallback.URL)
	cfg.Notifications.ES2PCallback.ACRURL = "https://operator.example/gsma/rsp2/es2plus/handleAcrRequest"
	require.NoError(t, cfg.Validate(RoleDP))

	// The default timeout is applied by the loader and is valid.
	require.Equal(t, 10*time.Second, time.Duration(cfg.Notifications.ES2PCallback.ACRTimeout))

	bad := []struct {
		name string
		mut  func(*CallbackConfig)
		want string
	}{
		{"relative acr_url", func(c *CallbackConfig) { c.ACRURL = "/gsma/rsp2/es2plus/handleAcrRequest" }, "not a valid absolute URL"},
		{"scheme only", func(c *CallbackConfig) { c.ACRURL = "operator.example/acr" }, "not a valid absolute URL"},
		{"negative timeout", func(c *CallbackConfig) {
			c.ACRURL = "https://operator.example/acr"
			c.ACRTimeout = Duration(-time.Second)
		}, "acr_timeout must be >= 0"},
		{"cert without key", func(c *CallbackConfig) {
			c.ACRURL = "https://operator.example/acr"
			c.ClientCertFile = "testdata/sgp26/x.pem"
		}, "must be set together"},
		{"missing cert file", func(c *CallbackConfig) {
			c.ACRURL = "https://operator.example/acr"
			c.ClientCertFile, c.ClientKeyFile = "testdata/nope.pem", "testdata/nope.key"
		}, "not found at"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := load()
			tc.mut(&cfg.Notifications.ES2PCallback)
			err := cfg.Validate(RoleDP)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}
