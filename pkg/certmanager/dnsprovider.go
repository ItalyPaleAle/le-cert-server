package certmanager

import (
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"

	"github.com/italypaleale/le-cert-server/pkg/config"
)

// createDNSProvider creates a DNS challenge provider based on the provider name
func (cm *certManager) createDNSProvider() (challenge.Provider, error) {
	cfg := config.Get()

	// Use lego's dynamic DNS provider resolver
	// This supports all DNS providers that lego supports
	// Credentials are written to the environment once at startup, see setDNSCredentialsEnv
	provider, err := dns.NewDNSChallengeProviderByName(cfg.LetsEncrypt.DNSProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s'; check provider name and ensure required environment variables are set: %w", cfg.LetsEncrypt.DNSProvider, err)
	}

	return provider, nil
}

// setDNSCredentialsEnv writes the configured DNS provider credentials to the process environment
// lego's name-based resolver reads these credentials only from the environment, so they are set once at startup rather than on every obtain/renew, which would needlessly mutate global state shared with other goroutines
// The credentials can also be provided as system environment variables, in which case dnsCredentials may be empty
func setDNSCredentialsEnv() error {
	cfg := config.Get()
	for key, value := range cfg.LetsEncrypt.DNSCredentials {
		err := os.Setenv(key, value)
		if err != nil {
			return fmt.Errorf("failed to set environment variable %s: %w", key, err)
		}
	}

	return nil
}
