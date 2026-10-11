package config

import (
	"os"
	"path/filepath"
	"testing"

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
	require.Error(t, validateOID("2..10"))
	require.Error(t, validateOID("2.abc"))
	require.Error(t, validateOID(""))
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
