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
	assert.Equal(t, map[string]string{"CF_DNS_API_TOKEN": "secret-token"}, c.GetDNSEnv())
}

func TestResolveDNSProvider_RawEnvName(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "CF_DNS_API_TOKEN: secret-token\n")

	err := c.Validate(testLogger())

	require.NoError(t, err)
	assert.Equal(t, map[string]string{"CF_DNS_API_TOKEN": "secret-token"}, c.GetDNSEnv())
}

func TestResolveDNSProvider_Alias(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "CLOUDFLARE_DNS_API_TOKEN: secret-token\n")

	err := c.Validate(testLogger())

	require.NoError(t, err)
	// The alias maps to the canonical env var that lego consumes
	assert.Equal(t, map[string]string{"CF_DNS_API_TOKEN": "secret-token"}, c.GetDNSEnv())
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

func TestResolveDNSProvider_EmptyCredentials(t *testing.T) {
	c := validConfig()
	// No dnsCredentials set: the zero-value node must validate cleanly with an empty env

	err := c.Validate(testLogger())

	require.NoError(t, err)
	assert.Empty(t, c.GetDNSEnv())
}
