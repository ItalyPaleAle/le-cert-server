package certmanager

import (
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/yourusername/cert-server/storage"
)

// createDNSProvider creates a DNS challenge provider based on the provider name
func (cm *CertManager) createDNSProvider() (challenge.Provider, error) {
	// Set environment variables for the DNS provider
	// These credentials can be provided via the config file or already set in the environment
	for key, value := range cm.dnsCreds {
		if err := os.Setenv(key, value); err != nil {
			return nil, fmt.Errorf("failed to set environment variable %s: %w", key, err)
		}
	}

	// Store DNS credentials in the database
	dnsCreds := &storage.DNSCredentials{
		Provider:    cm.dnsProvider,
		Credentials: cm.dnsCreds,
	}
	if err := cm.storage.SaveDNSCredentials(dnsCreds); err != nil {
		return nil, fmt.Errorf("failed to save DNS credentials: %w", err)
	}

	// Use lego's dynamic DNS provider resolver
	// This supports all DNS providers that lego supports
	provider, err := dns.NewDNSChallengeProviderByName(cm.dnsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s': %w (check provider name and ensure required environment variables are set)", cm.dnsProvider, err)
	}

	return provider, nil
}
