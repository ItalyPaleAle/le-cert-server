package config

import (
	"bytes"
	"log/slog"
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

// TestResolveDNSProvider_RenamedProviderCode verifies that a provider code renamed by lego is still accepted and is rewritten to the current code
func TestResolveDNSProvider_RenamedProviderCode(t *testing.T) {
	tests := []struct {
		configured string
		current    string
		yamlSrc    string
		assert     func(t *testing.T, pc dnsProviderConfig)
	}{
		{
			configured: "rfc2136",
			current:    "dnsupdate",
			yamlSrc:    "nameserver: ns.example.com:53\n",
			assert: func(t *testing.T, pc dnsProviderConfig) {
				t.Helper()
				cfg, ok := pc.(*DnsupdateConfig)
				require.True(t, ok, "expected a *DnsupdateConfig, got %T", pc)
				assert.Equal(t, "ns.example.com:53", cfg.Nameserver)
			},
		},
		{
			configured: "acme-dns",
			current:    "acmedns",
			yamlSrc:    "dnsAPIBase: https://auth.example.com\n",
			assert: func(t *testing.T, pc dnsProviderConfig) {
				t.Helper()
				cfg, ok := pc.(*AcmednsConfig)
				require.True(t, ok, "expected an *AcmednsConfig, got %T", pc)
				assert.Equal(t, "https://auth.example.com", cfg.DNSAPIBase)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.configured, func(t *testing.T) {
			c := validConfig()
			c.LetsEncrypt.DNSProvider = tt.configured
			c.LetsEncrypt.DNSCredentials = decodeCredentials(t, tt.yamlSrc)

			buf := &bytes.Buffer{}
			logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

			err := c.Validate(logger)
			require.NoError(t, err)

			// The code is rewritten so that logs and error messages elsewhere refer to the provider lego actually uses
			assert.Equal(t, tt.current, c.LetsEncrypt.DNSProvider)

			// The replacement takes the same credential keys, so the credentials must decode unchanged
			tt.assert(t, c.internal.dnsProviderConfig)

			// Using a renamed code is deprecated, so it must be surfaced rather than silently accepted
			out := buf.String()
			assert.Contains(t, out, "renamed")
			assert.Contains(t, out, "configured="+tt.configured)
			assert.Contains(t, out, "renamedTo="+tt.current)
		})
	}
}

// TestResolveDNSProvider_CurrentProviderCodeDoesNotWarn verifies that only renamed codes produce the deprecation warning
func TestResolveDNSProvider_CurrentProviderCodeDoesNotWarn(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "dnsAPIToken: secret-token\n")

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	err := c.Validate(logger)
	require.NoError(t, err)

	assert.Equal(t, "cloudflare", c.LetsEncrypt.DNSProvider)
	assert.Empty(t, buf.String())
}

// TestCurrentDNSProviderCode verifies that the generated rename lookup leaves codes it does not know alone
// An unknown code in particular must pass through unchanged, so the validation error names what was actually configured
func TestCurrentDNSProviderCode(t *testing.T) {
	tests := []string{"cloudflare", "not-a-provider"}
	for _, code := range tests {
		t.Run(code, func(t *testing.T) {
			got, renamed := currentDNSProviderCode(code)
			assert.Equal(t, code, got)
			assert.False(t, renamed)
		})
	}
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
