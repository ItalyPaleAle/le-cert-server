package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yaml "sigs.k8s.io/yaml/goyaml.v3"
)

// decodeCredentials parses a YAML snippet into a yaml.Node for use as DNSCredentials
func decodeCredentials(t *testing.T, src string) yaml.Node {
	t.Helper()
	var node yaml.Node
	err := yaml.Unmarshal([]byte(src), &node)
	require.NoError(t, err)
	// yaml.Unmarshal yields a document node; the mapping is its first child
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		return *node.Content[0]
	}
	return node
}

func TestResolveDNSProvider_NormalizedName(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "dnsAPIToken: secret-token\n")

	err := c.Validate(testLogger())
	require.NoError(t, err)

	// The decoded credentials must build a working lego provider without touching the environment
	provider, err := c.NewDNSProvider()
	require.NoError(t, err)
	assert.NotNil(t, provider)
}

func TestResolveDNSProvider_RawEnvName(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "CF_DNS_API_TOKEN: secret-token\n")

	err := c.Validate(testLogger())
	require.NoError(t, err)

	cf, ok := c.internal.dnsProviderConfig.(*CloudflareConfig)
	require.True(t, ok)
	assert.Equal(t, "secret-token", cf.DNSAPIToken)
}

func TestResolveDNSProvider_Alias(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "CLOUDFLARE_DNS_API_TOKEN: secret-token\n")

	err := c.Validate(testLogger())
	require.NoError(t, err)

	// The documented alias maps to the same field as the canonical env name
	cf, ok := c.internal.dnsProviderConfig.(*CloudflareConfig)
	require.True(t, ok)
	assert.Equal(t, "secret-token", cf.DNSAPIToken)
}

func TestResolveDNSProvider_UnknownKeyErrors(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "notARealKey: value\n")

	err := c.Validate(testLogger())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "notARealKey")
}

func TestResolveDNSProvider_UnknownProviderErrors(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSProvider = "not-a-provider"

	err := c.Validate(testLogger())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "dnsProvider")
}

func TestResolveDNSProvider_InvalidNumericValueErrors(t *testing.T) {
	c := validConfig()
	// ttl maps to an int field, so a non-numeric value must be rejected when building the provider
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "dnsAPIToken: secret-token\nttl: not-a-number\n")

	err := c.Validate(testLogger())
	require.NoError(t, err)

	_, err = c.NewDNSProvider()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl")
}
