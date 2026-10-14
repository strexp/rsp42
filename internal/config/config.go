// Package config loads and validates the single rsp42 configuration source.
//
// The configuration is a single YAML file (see config/config.example.yaml).
// Environment variables prefixed with RSP42_ override YAML values; nested keys
// use underscores, e.g. RSP42_SMDPP_FQDN overrides smdpp.fqdn.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the root configuration object.
type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	SMDpp         SMDppConfig         `mapstructure:"smdpp"`
	Certs         CertsConfig         `mapstructure:"certs"`
	Profiles      ProfilesConfig      `mapstructure:"profiles"`
	Notifications NotificationsConfig `mapstructure:"notifications"`
	SMDS          SMDSConfig          `mapstructure:"smds"`
	KMS           KMSConfig           `mapstructure:"kms"`
	Log           LogConfig           `mapstructure:"log"`
	Audit         AuditConfig         `mapstructure:"audit"`
}

// ServerConfig holds SM-DP+ process listeners.
type ServerConfig struct {
	Bind  string      `mapstructure:"bind"`
	ES9P  ListenerCfg `mapstructure:"es9p"`
	ES2P  ListenerCfg `mapstructure:"es2p"`
	Admin ListenerCfg `mapstructure:"admin"`
}

// ListenerCfg is a single HTTP listener (port + optional TLS).
type ListenerCfg struct {
	Port int    `mapstructure:"port"`
	TLS  TLSCfg `mapstructure:"tls"`
}

// TLSCfg configures TLS for a listener or client.
type TLSCfg struct {
	Enabled        bool   `mapstructure:"enabled"`
	CertFile       string `mapstructure:"cert_file"`
	KeyFile        string `mapstructure:"key_file"`
	ClientCAFile   string `mapstructure:"client_ca_file"`
	ClientCertFile string `mapstructure:"client_cert_file"`
	ClientKeyFile  string `mapstructure:"client_key_file"`
	CAFile         string `mapstructure:"ca_file"`
	MinVersion     string `mapstructure:"min_version"`
}

// SMDppConfig is the SM-DP+ specific configuration.
type SMDppConfig struct {
	FQDN                string     `mapstructure:"fqdn"`
	OID                 string     `mapstructure:"oid"`
	HostID              string     `mapstructure:"host_id"`
	Curve               string     `mapstructure:"curve"`
	TransactionIDLen    int        `mapstructure:"transaction_id_len"`
	SessionTTL          Duration   `mapstructure:"session_ttl"`
	DownloadTTL         Duration   `mapstructure:"download_ttl"`
	MaxDownloadAttempts int        `mapstructure:"max_download_attempts"`
	MaxCCAttempts       int        `mapstructure:"max_cc_attempts"`
	ES12                ES12Config `mapstructure:"es12"`
}

// ES12Config configures the SM-DP+ ES12 client used to register events with an SM-DS.
type ES12Config struct {
	Enabled             bool   `mapstructure:"enabled"`
	SMDSAddress         string `mapstructure:"smds_address"`
	RegisterOnConfirm   bool   `mapstructure:"register_on_confirm"`
	ForwardingIndicator bool   `mapstructure:"forwarding_indicator"`
	DeleteOnInstall     bool   `mapstructure:"delete_on_install"`
	TLS                 TLSCfg `mapstructure:"tls"`
}

// CertsConfig points at the on-disk certificate tree.
type CertsConfig struct {
	RootDir               string `mapstructure:"root_dir"`
	CI                    string `mapstructure:"ci"`
	EUM                   string `mapstructure:"eum"`
	EUICC                 string `mapstructure:"euicc"`
	DPAuth                string `mapstructure:"dp_auth"`
	DPPb                  string `mapstructure:"dp_pb"`
	DPTLS                 string `mapstructure:"dp_tls"`
	DSAuth                string `mapstructure:"ds_auth"`
	DSTLS                 string `mapstructure:"ds_tls"`
	AllowExpiredTestCerts bool   `mapstructure:"allow_expired_test_certs"`
	// Identities holds additional certificate sets, letting one deployment
	// serve eUICCs that propose different CI key identifiers (SGP.26 variants).
	Identities []CertsConfig `mapstructure:"identities"`
}

// ProfilesConfig configures the UPP template registry and personalization.
// Both are stored in the database and seeded via `rsp42 admin`.
type ProfilesConfig struct {
	// DefaultUPP pins a registry template name used when the eUICC's profile
	// version does not select one.
	DefaultUPP      string                `mapstructure:"default_upp"`
	Repository      string                `mapstructure:"repository"`
	Store           StoreConfig           `mapstructure:"store"`
	Personalization PersonalizationConfig `mapstructure:"personalization"`
	// PPRIds lists the Profile Policy Rules to attach to downloaded profiles
	// (SGP.22 §2.4a: 1 = PPR1 disabling not allowed, 2 = PPR2 deletion not
	// allowed).
	PPRIds []int `mapstructure:"ppr_ids"`
}

// StoreConfig is a SQLite DSN.
type StoreConfig struct {
	DSN string `mapstructure:"dsn"`
}

// PersonalizationConfig configures the personalization engine. Per-ICCID values
// live in the database; they are seeded with `rsp42 admin personalization import`.
type PersonalizationConfig struct {
	DefaultAlgorithm string `mapstructure:"default_algorithm"`
	ICCIDPoolPrefix  string `mapstructure:"iccid_pool_prefix"`
	IMSIPoolPrefix   string `mapstructure:"imsi_pool_prefix"`
}

// NotificationsConfig configures outbound ES2+ callbacks.
type NotificationsConfig struct {
	ES2PCallback CallbackConfig `mapstructure:"es2p_callback"`
}

// CallbackConfig is an HTTP callback target.
type CallbackConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	URL     string `mapstructure:"url"`
	// ACRURL is the optional Operator ES2+.HandleAcrRequest endpoint.
	ACRURL         string   `mapstructure:"acr_url"`
	ClientCertFile string   `mapstructure:"client_cert_file"`
	ClientKeyFile  string   `mapstructure:"client_key_file"`
	CAFile         string   `mapstructure:"ca_file"`
	MaxAttempts    int      `mapstructure:"max_attempts"`
	RetryInterval  Duration `mapstructure:"retry_interval"`
}

// SMDSConfig configures the SM-DS process.
type SMDSConfig struct {
	Enabled  bool          `mapstructure:"enabled"`
	Role     string        `mapstructure:"role"`
	FQDN     string        `mapstructure:"fqdn"`
	OID      string        `mapstructure:"oid"`
	Curve    string        `mapstructure:"curve"`
	EventTTL Duration      `mapstructure:"event_ttl"`
	DSAuth   CertKeyConfig `mapstructure:"dsauth"`
	DSTLS    CertKeyConfig `mapstructure:"dstls"`
	Cascade  CascadeConfig `mapstructure:"cascade"`
	Server   SMDSServer    `mapstructure:"server"`
	Store    StoreConfig   `mapstructure:"store"`
}

// CertKeyConfig is a DER/PEM cert + PEM key pair.
type CertKeyConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

// CascadeConfig configures Alternative -> Root SM-DS cascading.
type CascadeConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	RootAddress string `mapstructure:"root_address"`
	TLS         TLSCfg `mapstructure:"tls"`
}

// SMDSServer holds SM-DS listeners.
type SMDSServer struct {
	Bind  string      `mapstructure:"bind"`
	ES11  ListenerCfg `mapstructure:"es11"`
	ES12  ListenerCfg `mapstructure:"es12"`
	Admin ListenerCfg `mapstructure:"admin"`
}

// KMSConfig configures the key management service.
type KMSConfig struct {
	Provider string `mapstructure:"provider"`
	KEKFile  string `mapstructure:"kek_file"`
	KEKHex   string `mapstructure:"kek_hex"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// AuditConfig configures the audit sink.
type AuditConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Sink    string `mapstructure:"sink"`
	File    string `mapstructure:"file"`
}

// Duration is a time.Duration that unmarshals from a YAML string like "30m".
type Duration time.Duration

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler via viper's default decoding.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		var n int64
		if err2 := unmarshal(&n); err2 == nil {
			*d = Duration(time.Duration(n))
			return nil
		}
		return err
	}
	return d.UnmarshalText([]byte(s))
}

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Load reads the YAML config at path, applies RSP42_ env overrides, and
// validates the result for the given roles. Pass RoleDP for the SM-DP+ process,
// RoleDS for the SM-DS process, and RolePreflight to verify everything.
func Load(path string, roles ...Role) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("RSP42")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg, viper.DecodeHook(durationHook())); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	if len(roles) == 0 {
		roles = []Role{RolePreflight}
	}
	for _, r := range roles {
		if err := cfg.Validate(r); err != nil {
			return nil, err
		}
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.bind", "0.0.0.0")
	v.SetDefault("server.es9p.port", 8443)
	v.SetDefault("server.es2p.port", 8444)
	v.SetDefault("server.admin.port", 9000)
	v.SetDefault("smdpp.curve", "nist")
	v.SetDefault("smdpp.host_id", "0000000000000000")
	v.SetDefault("smdpp.transaction_id_len", 16)
	v.SetDefault("smdpp.session_ttl", "30m")
	v.SetDefault("smdpp.download_ttl", "24h")
	v.SetDefault("smdpp.max_download_attempts", 5)
	v.SetDefault("smdpp.max_cc_attempts", 3)
	v.SetDefault("certs.root_dir", "testdata/sgp26")
	v.SetDefault("certs.ci", "CertificateIssuer")
	v.SetDefault("certs.eum", "EUM")
	v.SetDefault("certs.euicc", "eUICC")
	v.SetDefault("certs.dp_auth", "SM-DP+/DPauth")
	v.SetDefault("certs.dp_pb", "SM-DP+/DPpb")
	v.SetDefault("certs.dp_tls", "SM-DP+/DPtls")
	v.SetDefault("certs.ds_auth", "SM-DS/DSauth")
	v.SetDefault("certs.ds_tls", "SM-DS/DStls")
	v.SetDefault("certs.allow_expired_test_certs", true)
	v.SetDefault("notifications.es2p_callback.max_attempts", 5)
	v.SetDefault("notifications.es2p_callback.retry_interval", "30s")
	v.SetDefault("profiles.repository", "sqlite")
	v.SetDefault("profiles.store.dsn", "file:rsp42.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	v.SetDefault("profiles.personalization.default_algorithm", "milenage")
	v.SetDefault("smds.role", "root")
	v.SetDefault("smds.curve", "nist")
	v.SetDefault("smds.event_ttl", "720h")
	v.SetDefault("smds.server.es11.port", 9443)
	v.SetDefault("smds.server.es12.port", 9444)
	v.SetDefault("smds.server.admin.port", 9100)
	v.SetDefault("smds.store.dsn", "file:rsp42-smds.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	v.SetDefault("kms.provider", "file")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.sink", "db")
}

// Role selects which validation profile to apply.
type Role int

const (
	// RolePreflight validates every section (used by tests and admin tooling).
	RolePreflight Role = iota
	// RoleDP validates the SM-DP+ process configuration.
	RoleDP
	// RoleDS validates the SM-DS process configuration.
	RoleDS
)

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
