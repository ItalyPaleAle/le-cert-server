package config

import (
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
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
	// You must configure exactly one auth method (jwt or psk)
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

	// If true, calls to the healthcheck endpoint (`/healthz`) are not included in the logs.
	// +default true
	OmitHealthChecks bool `yaml:"omitHealthChecks"`

	// If true, emits logs formatted as JSON, otherwise uses a text-based structured log format.
	// Defaults to false if a TTY is attached (e.g. when running the binary directly in the terminal or in development); true otherwise.
	JSON bool `yaml:"json"`
}

// ConfigServer represents server configuration
type ConfigServer struct {
	// Listener type for the API server.
	// Supported values: "tcp" (default) and "tsnet".
	// When set to "tsnet", the server listens on a Tailscale netstack and always serves HTTPS using Tailscale-provided certificates.
	// +default "tcp"
	Listener string `yaml:"listener"`

	// Address to bind the API server to
	// Set to "0.0.0.0" for listening on all interfaces
	// This is ignored when using "tsnet" as listener
	// +default "127.0.0.1"
	Bind string `yaml:"bind"`

	// Port for the API server to listen on
	// +default 7701 ("tcp" listner) or 443 ("tsnet" listener)
	Port int `yaml:"port"`

	// TLS configuration, used when listener is set to "tcp".
	TLS ConfigServerTLS `yaml:"tls"`

	// TSNet configuration, used when listener is set to "tsnet".
	TSNet ConfigServerTSNet `yaml:"tsnet"`
}

// ConfigServerTLS holds TLS configuration for TCP listener
type ConfigServerTLS struct {
	// If set, fetch the server certificate from Let's Encrypt for the given domain
	LetsEncryptDomain string `yaml:"letsEncryptDomain"`

	// Path where to load TLS certificates from, when not using Let's Encrypt.
	// Within the folder, the files must be named `tls-cert.pem` and `tls-key.pem`. The application watches for changes in this folder and automatically reloads the TLS certificates when they're updated.
	// If empty, certificates are loaded from the same folder where the loaded `config.yaml` is located.
	// +default the same folder as the `config.yaml` file
	Path string `yaml:"path"`

	// Full, PEM-encoded TLS certificate, when not using Let's Encrypt.
	// Using `certPEM` and `keyPEM` is an alternative method of passing TLS certificates than using `path`.
	CertPEM string `yaml:"certPEM"` //nolint:tagliatelle

	// Full, PEM-encoded TLS key, when not using Let's Encrypt.
	// Using `certPEM` and `keyPEM` is an alternative method of passing TLS certificates than using `path`.
	KeyPEM string `yaml:"keyPEM"` //nolint:tagliatelle
}

// ConfigServerTSNet holds tsnet configuration
type ConfigServerTSNet struct {
	// Hostname to use for the tsnet node.
	Hostname string `yaml:"hostname"`

	// AuthKey can be used to authenticate the tsnet node automatically.
	// If empty, tsnet will rely on existing state in the database.
	AuthKey string `yaml:"authKey"`

	// Directory where tsnet stores its state.
	// If empty, defaults to a folder next to the loaded config file.
	StateDir string `yaml:"stateDir"`

	// If true, the tsnet node is ephemeral (not persisted in the tailnet).
	// +default false
	Ephemeral bool `yaml:"ephemeral"`
}

// ConfigLetsEncrypt holds Let's Encrypt configuration
type ConfigLetsEncrypt struct {
	// Email address for Let's Encrypt registration
	// +required
	Email string `yaml:"email"`

	// Use staging Let's Encrypt environment
	// Set to true for testing
	// +default false
	Staging bool `yaml:"staging"`

	// DNS provider for DNS-01 challenge
	// All DNS providers supported by lego can be used here
	// See full list: https://go-acme.github.io/lego/dns/
	// Examples: "cloudflare", "route53", "digitalocean", "godaddy", "namecheap", etc.
	// +required
	DNSProvider string `yaml:"dnsProvider"`

	// DNS provider credentials (provider-specific environment variables)
	// These will be set as environment variables for the DNS provider
	// You can also set these as system environment variables instead of in the config
	// Refer to the Lego provider docs for the supported values: https://go-acme.github.io/lego/dns/
	// Examples:
	//   - Cloudflare: set CF_DNS_API_TOKEN
	//   - AWS Route53, set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
	DNSCredentials map[string]string `yaml:"dnsCredentials"`

	// Certificate renewal threshold in days
	// +default 30
	RenewalDays int `yaml:"renewalDays"`
}

// ConfigDatabase holds database configuration
type ConfigDatabase struct {
	// Path to SQLite database file or connection string
	// +default "le-cert-server.db" in the current directory
	Path string `yaml:"path"`
}

// ConfigAuth holds auth configuration
type ConfigAuth struct {
	// OAuth2/OIDC (JWT) Authentication (recommended for multi-user environments)
	// One and only one of `jwt`, `psk`, or `tsnet` must be set
	JWT *ConfigAuthJWT `yaml:"jwt,omitempty"`

	// PSK (Pre-Shared Key) authentication configuration
	// One and only one of `jwt`, `psk`, or `tsnet` must be set
	PSK *ConfigAuthPSK `yaml:"psk,omitempty"`

	// Tailscale Identity authentication (only available when using tsnet listener)
	// To enable the use of the TSNet identity with the default options, an empty object (e.g. `tsnet: {}`) is sufficient
	// One and only one of `jwt`, `psk`, or `tsnet` must be set
	TSNet *ConfigAuthTSNet `yaml:"tsnet,omitempty"`
}

// ConfigAuthJWT holds JWT/OAuth2 authentication configuration
type ConfigAuthJWT struct {
	// OAuth2 issuer URL for token validation (OIDC discovery endpoint)
	// Examples:
	//   - Google: "https://accounts.google.com"
	//   - Microsoft Entra ID: "https://login.microsoftonline.com/{tenant}/v2.0"
	//   - Auth0: "https://your-tenant.auth0.com"
	//   - Keycloak: "https://keycloak.example.com/realms/your-realm"
	// +required
	IssuerURL string `yaml:"issuerUrl"`

	// Expected audience (client ID) for token validation
	// This should match the client ID from your OAuth2 provider
	// +required
	Audience string `yaml:"audience"`

	// Required scopes that tokens must have (optional)
	RequiredScopes []string `yaml:"requiredScopes,omitempty"`
}

// ConfigAuthPSK holds pre-shared key authentication configuration
type ConfigAuthPSK struct {
	// Pre-Shared Key Authentication (simpler setup, good for internal services)
	// Must be at least 16 characters
	// Generate with: `openssl rand -base64 32`
	Key string `yaml:"key"`
}

// ConfigAuthTSNet holds Tailscale identity authentication configuration
type ConfigAuthTSNet struct {
	// If non-empty, requires the Tailnet of the user to match this value
	// +example "yourtailnet.ts.net"
	AllowedTailnet string `yaml:"allowedTailnet"`
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
	if c.Server.Port < 0 {
		return errors.New("configuration option 'server.port' must not be negative")
	}
	if c.LetsEncrypt.Email == "" {
		return errors.New("configuration option 'letsEncrypt.email' is required")
	}
	if c.LetsEncrypt.DNSProvider == "" {
		return errors.New("configuration option 'letsEncrypt.dnsProvider' is required")
	}

	switch c.Server.Listener {
	case "tcp":
		if c.Server.Port == 0 {
			// In tcp mode, the default port is 7401
			c.Server.Port = 7401
		}
		if c.Server.Bind == "" {
			return errors.New("configuration option 'server.bind' is required")
		}

	case "tsnet":
		if c.Server.Port == 0 {
			// In tsnet mode, the default port is 443
			c.Server.Port = 443
		}
		// In tsnet mode, the API server uses HTTPS with Tailscale-provided certificates.
		// We intentionally do not require server.bind nor server-side Let's Encrypt configuration.

	default:
		return errors.New("configuration option 'server.listener' must be one of 'tcp' or 'tsnet'")
	}

	// Validate auth configuration based on type
	if countSetProperties(c.Auth) != 1 {
		return errors.New("configuration section 'auth' must contain one and only one of 'jwt', 'psk', or 'tsnet'")
	}

	switch {
	case c.Auth.JWT != nil:
		if c.Auth.JWT.IssuerURL == "" {
			return errors.New("configuration option 'auth.jwt.issuerURL' is required when using JWT authentication")
		}
		if c.Auth.JWT.Audience == "" {
			return errors.New("configuration option 'auth.jwt.audience' is required when using JWT authentication")
		}
	case c.Auth.PSK != nil:
		if c.Auth.PSK.Key == "" {
			return errors.New("configuration option 'auth.psk.key' is required when using PSK authentication")
		}
		if len(c.Auth.PSK.Key) < 16 {
			return errors.New("configuration option 'auth.psk.key' must be at least 16 characters long")
		}
	case c.Auth.TSNet != nil:
		// TSNet auth can only be used with tsnet listener
		if c.Server.Listener != "tsnet" {
			return errors.New("configuration option 'auth.tsnet' can only be used when 'server.listener' is set to 'tsnet'")
		}
	default:
		return errors.New("configuration section 'auth' must contain one and only one of 'jwt', 'psk', or 'tsnet'")
	}

	return nil
}

func countSetProperties(s any) int {
	typ := reflect.TypeOf(s)
	val := reflect.ValueOf(s)

	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
		val = val.Elem()
	}
	if typ.Kind() != reflect.Struct {
		// Indicates a development-time error
		panic("param must be a struct")
	}

	var count int
	for i := range val.NumField() {
		field := val.Field(i)
		if field.IsValid() && !field.IsZero() {
			count++
		}
	}

	return count
}
