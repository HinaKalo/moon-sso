// Package config loads the server configuration from a TOML file.
// Secrets are never stored inline: they are read from files (normally
// systemd credentials) referenced by the configuration.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

type Config struct {
	Server   Server   `toml:"server"`
	Database Database `toml:"database"`
	Secrets  Secrets  `toml:"secrets"`
	Storage  Storage  `toml:"storage"`
	Security Security `toml:"security"`
	Tokens   Tokens   `toml:"tokens"`
	Log      Log      `toml:"log"`
}

type Server struct {
	PublicListen   string   `toml:"public_listen"`
	AdminListen    string   `toml:"admin_listen"`
	PublicURL      string   `toml:"public_url"`
	AdminURL       string   `toml:"admin_url"`
	TrustedProxies []string `toml:"trusted_proxies"`
	// Environment name shown in the UI and logs, e.g. "prod" or "staging".
	Environment     string   `toml:"environment"`
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
	// InsecureCookies disables the Secure flag and __Host- prefix. Only for local development over http.
	InsecureCookies bool `toml:"insecure_cookies"`
}

type Database struct {
	DSNFile         string   `toml:"dsn_file"`
	DSN             string   `toml:"-"`
	MaxOpenConns    int      `toml:"max_open_conns"`
	MaxIdleConns    int      `toml:"max_idle_conns"`
	ConnMaxLifetime Duration `toml:"conn_max_lifetime"`
}

type Secrets struct {
	MasterKeyFile string `toml:"master_key_file"`
}

type Storage struct {
	DataDir string `toml:"data_dir"`
}

type Security struct {
	ArgonMemoryKiB   uint32   `toml:"argon_memory_kib"`
	ArgonTime        uint32   `toml:"argon_time"`
	ArgonParallelism uint8    `toml:"argon_parallelism"`
	ArgonConcurrency int      `toml:"argon_concurrency"`
	ArgonQueueWait   Duration `toml:"argon_queue_wait"`
}

type Tokens struct {
	AccessTTL          Duration `toml:"access_ttl"`
	IDTokenTTL         Duration `toml:"id_token_ttl"`
	CodeTTL            Duration `toml:"code_ttl"`
	RefreshIdleTTL     Duration `toml:"refresh_idle_ttl"`
	RefreshAbsoluteTTL Duration `toml:"refresh_absolute_ttl"`
	RefreshGrace       Duration `toml:"refresh_grace"`
	SessionIdleTTL     Duration `toml:"session_idle_ttl"`
	SessionAbsoluteTTL Duration `toml:"session_absolute_ttl"`
}

type Log struct {
	Level  string `toml:"level"`
	Format string `toml:"format"` // json | text
}

// Load reads the file at path, applies defaults, resolves secret files and validates.
func Load(path string) (*Config, error) {
	c := Default()
	md, err := toml.DecodeFile(path, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		return nil, fmt.Errorf("config: unknown keys %v", undec)
	}
	if err := c.resolve(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func Default() *Config {
	return &Config{
		Server: Server{
			PublicListen:    "127.0.0.1:8601",
			AdminListen:     "127.0.0.1:8602",
			PublicURL:       "https://sso.moonl.cloud",
			AdminURL:        "https://sso-admin.moonl.cloud",
			TrustedProxies:  []string{"127.0.0.1/32", "::1/128"},
			Environment:     "prod",
			ShutdownTimeout: Duration{15 * time.Second},
		},
		Database: Database{MaxOpenConns: 40, MaxIdleConns: 20, ConnMaxLifetime: Duration{30 * time.Minute}},
		Storage:  Storage{DataDir: "/var/lib/moon-sso"},
		Security: Security{
			ArgonMemoryKiB: 19 * 1024, ArgonTime: 2, ArgonParallelism: 1,
			ArgonConcurrency: 2, ArgonQueueWait: Duration{5 * time.Second},
		},
		Tokens: Tokens{
			AccessTTL:          Duration{10 * time.Minute},
			IDTokenTTL:         Duration{10 * time.Minute},
			CodeTTL:            Duration{60 * time.Second},
			RefreshIdleTTL:     Duration{30 * 24 * time.Hour},
			RefreshAbsoluteTTL: Duration{180 * 24 * time.Hour},
			RefreshGrace:       Duration{60 * time.Second},
			SessionIdleTTL:     Duration{30 * 24 * time.Hour},
			SessionAbsoluteTTL: Duration{90 * 24 * time.Hour},
		},
		Log: Log{Level: "info", Format: "json"},
	}
}

// expandCredential replaces ${CREDENTIALS_DIRECTORY} (set by systemd LoadCredential=).
func expandCredential(p, base string) string {
	p = os.Expand(p, func(k string) string {
		if k == "CREDENTIALS_DIRECTORY" {
			return os.Getenv(k)
		}
		return "${" + k + "}"
	})
	if p != "" && !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	return p
}

func readSecretFile(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (c *Config) resolve(base string) error {
	c.Secrets.MasterKeyFile = expandCredential(c.Secrets.MasterKeyFile, base)
	c.Database.DSNFile = expandCredential(c.Database.DSNFile, base)
	if c.Database.DSNFile != "" {
		dsn, err := readSecretFile(c.Database.DSNFile)
		if err != nil {
			return fmt.Errorf("config: database dsn: %w", err)
		}
		c.Database.DSN = dsn
	}
	if env := os.Getenv("MOON_SSO_DSN"); env != "" {
		c.Database.DSN = env
	}
	return nil
}

func (c *Config) Validate() error {
	var errs []error
	for name, raw := range map[string]string{"server.public_url": c.Server.PublicURL, "server.admin_url": c.Server.AdminURL} {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
			errs = append(errs, fmt.Errorf("%s must be an absolute origin URL", name))
		}
	}
	c.Server.PublicURL = strings.TrimSuffix(c.Server.PublicURL, "/")
	c.Server.AdminURL = strings.TrimSuffix(c.Server.AdminURL, "/")
	if c.Database.DSN == "" {
		errs = append(errs, errors.New("database.dsn_file (or MOON_SSO_DSN) is required"))
	}
	if c.Secrets.MasterKeyFile == "" {
		errs = append(errs, errors.New("secrets.master_key_file is required"))
	}
	if c.Security.ArgonConcurrency < 1 {
		errs = append(errs, errors.New("security.argon_concurrency must be >= 1"))
	}
	if c.Tokens.AccessTTL.Duration < time.Minute || c.Tokens.AccessTTL.Duration > time.Hour {
		errs = append(errs, errors.New("tokens.access_ttl must be between 1m and 1h"))
	}
	if c.Tokens.RefreshIdleTTL.Duration > c.Tokens.RefreshAbsoluteTTL.Duration {
		errs = append(errs, errors.New("tokens.refresh_idle_ttl must not exceed refresh_absolute_ttl"))
	}
	if c.Tokens.SessionIdleTTL.Duration > c.Tokens.SessionAbsoluteTTL.Duration {
		errs = append(errs, errors.New("tokens.session_idle_ttl must not exceed session_absolute_ttl"))
	}
	return errors.Join(errs...)
}

// Issuer is the OIDC issuer identifier.
func (c *Config) Issuer() string { return c.Server.PublicURL }
