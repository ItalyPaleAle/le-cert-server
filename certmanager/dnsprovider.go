package certmanager

import (
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"

	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/storage"
)

// createDNSProvider creates a DNS challenge provider based on the provider name
func (cm *CertManager) createDNSProvider() (challenge.Provider, error) {
	cfg := config.Get()

	// Set environment variables for the DNS provider
	// These credentials can be provided via the config file or already set in the environment
	for key, value := range cfg.LetsEncrypt.DNSCredentials {
		err := os.Setenv(key, value)
		if err != nil {
			return nil, fmt.Errorf("failed to set environment variable %s: %w", key, err)
		}
	}

	// Store DNS credentials in the database
	dnsCreds := &storage.DNSCredentials{
		Provider:    cfg.LetsEncrypt.DNSProvider,
		Credentials: cfg.LetsEncrypt.DNSCredentials,
	}
	err := cm.storage.SaveDNSCredentials(dnsCreds)
	if err != nil {
		return nil, fmt.Errorf("failed to save DNS credentials: %w", err)
	}

	// Use lego's dynamic DNS provider resolver
	// This supports all DNS providers that lego supports
	provider, err := dns.NewDNSChallengeProviderByName(cfg.LetsEncrypt.DNSProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s'; check provider name and ensure required environment variables are set: %w", cfg.LetsEncrypt.DNSProvider, err)
	}

	return provider, nil
}
