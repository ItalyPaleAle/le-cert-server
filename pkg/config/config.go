package config

import (
	"encoding/json"
	"errors"
	"log/slog"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	Server ConfigServer `yaml:"server"`

	// Let's Encrypt configuration
	LetsEncrypt ConfigLetsEncrypt `yaml:"letsEncrypt"`

	// Database configuration
	Database ConfigDatabase `yaml:"database"`

	// Auth configuration
	Auth ConfigAuth `yaml:"auth"`

	// Logs contains configuration for logging
	Logs ConfigLogs `yaml:"logs"`

	// Dev is meant for development only; it's undocumented
	Dev ConfigDev `yaml:"-"`

	// Internal keys
	internal internal `yaml:"-"`
}

// ConfigLogs represents logging configuration
type ConfigLogs struct {
	// Controls log level and verbosity. Supported values: `debug`, `info` (default), `warn`, `error`.
	// +default "info"
	Level string `yaml:"level"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// Defaults to false if a TTY is attached (e.g. when running the binary directly in the terminal or in development); true otherwise.
	JSON bool `yaml:"json"`
}

// ConfigServer represents server configuration
type ConfigServer struct {
	// Address to bind to
	// +default "127.0.0.1"
	Bind string `yaml:"bind"`

	// Port to listen on
	// +default 7701
	Port int `yaml:"port"`

	// TLS certificate path for the server itself
	TLSCertPath string `yaml:"tlsCertPath"`

	// TLS key path for the server itself
	TLSKeyPath string `yaml:"tlsKeyPath"`
}

// ConfigLetsEncrypt holds Let's Encrypt configuration
type ConfigLetsEncrypt struct {
	// Email address for Let's Encrypt registration
	Email string `yaml:"email"`

	// Use staging environment (for testing)
	// +default false
	Staging bool `yaml:"staging"`

	// DNS provider (e.g., "cloudflare", "route53", "digitalocean")
	DNSProvider string `yaml:"dnsProvider"`

	// DNS provider credentials (provider-specific)
	DNSCredentials map[string]string `yaml:"dnsCredentials"`

	// Certificate renewal threshold in days
	// +default 30
	RenewalDays int `yaml:"renewalDays"`

	// Domain for the initial certificate (for the server itself)
	Domain string `yaml:"domain"`
}

// ConfigDatabase holds database configuration
type ConfigDatabase struct {
	// Path to SQLite database file
	Path string `yaml:"path"`
}

// ConfigAuth holds auth configuration
type ConfigAuth struct {
	// OAuth2 issuer URL for token validation (OIDC discovery endpoint)
	// Example: "https://accounts.google.com" or "https://login.microsoftonline.com/{tenant}/v2.0"
	IssuerURL string `yaml:"issuerUrl"`

	// Expected audience (client ID) for token validation
	Audience string `yaml:"audience"`

	// Required scopes (optional)
	RequiredScopes []string `yaml:"requiredScopes,omitempty"`
}

// ConfigDev includes options using during development only
type ConfigDev struct {
}

// Internal properties
type internal struct {
	instanceID       string
	configFileLoaded string // Path to the config file that was loaded
}

// String implements fmt.Stringer and prints out the config for debugging
func (c *Config) String() string {
	//nolint:errchkjson,musttag
	enc, _ := json.Marshal(c)
	return string(enc)
}

// GetLoadedConfigPath returns the path to the config file that was loaded
func (c *Config) GetLoadedConfigPath() string {
	return c.internal.configFileLoaded
}

// SetLoadedConfigPath sets the path to the config file that was loaded
func (c *Config) SetLoadedConfigPath(filePath string) {
	c.internal.configFileLoaded = filePath
}

// GetInstanceID returns the instance ID.
func (c *Config) GetInstanceID() string {
	return c.internal.instanceID
}

// Validates the configuration and performs some sanitization
func (c *Config) Validate(logger *slog.Logger) error {
	// Check required fields
	if c.Server.Bind == "" {
		return errors.New("configuration option 'server.bind' is required")
	}
	if c.Server.Port <= 0 {
		return errors.New("configuration option 'server.port' is required")
	}
	if c.LetsEncrypt.Email == "" {
		return errors.New("configuration option 'letLetsEncrypt.Email' is required")
	}
	if c.LetsEncrypt.DNSProvider == "" {
		return errors.New("configuration option 'letLetsEncrypt.DNSProvider' is required")
	}
	if c.Auth.IssuerURL == "" {
		return errors.New("configuration option 'auth.issuerURL' is required")
	}
	if c.Auth.Audience == "" {
		return errors.New("configuration option 'auth.audience' is required")
	}

	return nil
}
