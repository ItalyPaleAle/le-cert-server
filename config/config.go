package config

import (
	"fmt"
	"os"

	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

// Config holds the application configuration
type Config struct {
	// Server configuration
	Server ServerConfig `yaml:"server"`

	// Let's Encrypt configuration
	LetsEncrypt LetsEncryptConfig `yaml:"letsEncrypt"`

	// Database configuration
	Database DatabaseConfig `yaml:"database"`

	// OAuth2 configuration
	OAuth2 OAuth2Config `yaml:"oauth2"`
}

// ServerConfig holds the HTTP server configuration
type ServerConfig struct {
	// Address to bind the HTTPS server (e.g., ":8443")
	Address string `yaml:"address"`

	// TLS certificate path for the server itself
	TLSCertPath string `yaml:"tlsCertPath"`

	// TLS key path for the server itself
	TLSKeyPath string `yaml:"tlsKeyPath"`
}

// LetsEncryptConfig holds Let's Encrypt configuration
type LetsEncryptConfig struct {
	// Email address for Let's Encrypt registration
	Email string `yaml:"email"`

	// Use staging environment (for testing)
	Staging bool `yaml:"staging"`

	// DNS provider (e.g., "cloudflare", "route53", "digitalocean")
	DNSProvider string `yaml:"dnsProvider"`

	// DNS provider credentials (provider-specific)
	DNSCredentials map[string]string `yaml:"dnsCredentials"`

	// Certificate renewal threshold in days (default: 30)
	RenewalDays int `yaml:"renewalDays"`

	// Domain for the initial certificate (for the server itself)
	Domain string `yaml:"domain"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	// Path to SQLite database file
	Path string `yaml:"path"`
}

// OAuth2Config holds OAuth2 configuration
type OAuth2Config struct {
	// Bearer token for authentication (simple version)
	// In production, you'd use a proper OAuth2 provider
	BearerToken string `yaml:"bearerToken"`

	// Optional: OAuth2 issuer URL for token validation
	IssuerURL string `yaml:"issuerUrl,omitempty"`

	// Optional: OAuth2 audience
	Audience string `yaml:"audience,omitempty"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	config := Config{}

	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to open config file '%s': %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	yamlDec := yaml.NewDecoder(f)
	yamlDec.KnownFields(true)
	err = yamlDec.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config file '%s': %w", path, err)
	}

	// Set defaults
	if config.LetsEncrypt.RenewalDays <= 0 {
		config.LetsEncrypt.RenewalDays = 30
	}

	return &config, nil
}
