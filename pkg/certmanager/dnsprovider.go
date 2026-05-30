package certmanager

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/italypaleale/le-cert-server/pkg/config"
)

// createDNSProvider creates a DNS challenge provider for the configured provider
// Credentials are passed to lego using strong types and are never written to the process environment
func (cm *certManager) createDNSProvider() (challenge.Provider, error) {
	cfg := config.Get()

	provider, err := cfg.NewDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s': %w", cfg.LetsEncrypt.DNSProvider, err)
	}

	return provider, nil
}
