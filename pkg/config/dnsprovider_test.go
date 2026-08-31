package config

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
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

// TestResolveDNSProvider_NonScalarCredentials verifies the credential kinds that lego does not take as a plain scalar
// These are the fields the generator used to drop, which left some providers unusable because a required credential had no key
func TestResolveDNSProvider_NonScalarCredentials(t *testing.T) {
	tests := []struct {
		provider string
		yamlSrc  string
		assert   func(t *testing.T, pc dnsProviderConfig)
	}{
		{
			// PowerDNS needs the API URL, which lego holds as a *url.URL
			provider: "pdns",
			yamlSrc:  "apiKey: secret\napiURL: http://pdns.example.com:8081\n",
			assert: func(t *testing.T, pc dnsProviderConfig) {
				t.Helper()
				cfg, ok := pc.(*PdnsConfig)
				require.True(t, ok, "expected a *PdnsConfig, got %T", pc)
				assert.Equal(t, "http://pdns.example.com:8081", cfg.APIURL)
			},
		},
		{
			// dnsHome.de needs one password per domain, which lego holds as a map
			provider: "dnshomede",
			yamlSrc:  "credentials: example.com:pw1,example.org:pw2\n",
			assert: func(t *testing.T, pc dnsProviderConfig) {
				t.Helper()
				cfg, ok := pc.(*DnshomedeConfig)
				require.True(t, ok, "expected a *DnshomedeConfig, got %T", pc)
				assert.Equal(t, "example.com:pw1,example.org:pw2", cfg.Credentials)
			},
		},
		{
			// The zone list is a []string in lego
			provider: "dnsupdate",
			yamlSrc:  "nameserver: ns.example.com:53\nzones: example.com,example.org\n",
			assert: func(t *testing.T, pc dnsProviderConfig) {
				t.Helper()
				cfg, ok := pc.(*DnsupdateConfig)
				require.True(t, ok, "expected a *DnsupdateConfig, got %T", pc)
				assert.Equal(t, "example.com,example.org", cfg.Zones)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			c := validConfig()
			c.LetsEncrypt.DNSProvider = tt.provider
			c.LetsEncrypt.DNSCredentials = decodeCredentials(t, tt.yamlSrc)

			err := c.Validate(testLogger())
			require.NoError(t, err)

			tt.assert(t, c.internal.dnsProviderConfig)

			// The value must also survive conversion into the lego config, which is where the parsing happens
			provider, err := c.NewDNSProvider()
			require.NoError(t, err)
			assert.NotNil(t, provider)
		})
	}
}

// TestResolveDNSProvider_InvalidNonScalarValueErrors verifies that malformed non-scalar credentials are rejected when the provider is built
// The value is parsed before lego is handed the configuration, so these cases never reach the provider's API
func TestResolveDNSProvider_InvalidNonScalarValueErrors(t *testing.T) {
	tests := []struct {
		provider string
		yamlSrc  string
		wantErr  string
	}{
		{
			provider: "dnshomede",
			yamlSrc:  "credentials: not-a-pair\n",
			wantErr:  "credentials",
		},
		{
			// huaweicloud holds the TTL as an int32, so it takes a different parsing path than the usual int
			provider: "huaweicloud",
			yamlSrc:  "accessKeyID: ak\nsecretAccessKey: sk\nregion: cn-north-1\nttl: not-a-number\n",
			wantErr:  "ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			c := validConfig()
			c.LetsEncrypt.DNSProvider = tt.provider
			c.LetsEncrypt.DNSCredentials = decodeCredentials(t, tt.yamlSrc)

			err := c.Validate(testLogger())
			require.NoError(t, err)

			_, err = c.NewDNSProvider()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestResolveDNSProvider_AzureEnvironment verifies that the Azure cloud is selectable by name
// lego holds it as an Azure SDK configuration rather than a string, so the name is resolved when the provider is built
func TestResolveDNSProvider_AzureEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		want    cloud.Configuration
		wantErr bool
	}{
		{name: "public", want: cloud.AzurePublic},
		{name: "usgovernment", want: cloud.AzureGovernment},
		{name: "china", want: cloud.AzureChina},
		// The names are accepted regardless of case, unlike lego's environment variable
		{name: "USGovernment", want: cloud.AzureGovernment},
		{name: "not-a-cloud", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAzureEnvironment(tt.name)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.name)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestResolveDNSProvider_AzureEnvironmentInvalidValueErrors verifies that an unknown cloud name is rejected when the provider is built
func TestResolveDNSProvider_AzureEnvironmentInvalidValueErrors(t *testing.T) {
	c := validConfig()
	c.LetsEncrypt.DNSProvider = "azuredns"
	c.LetsEncrypt.DNSCredentials = decodeCredentials(t, "clientID: id\nclientSecret: secret\ntenantID: tenant\nenvironment: not-a-cloud\n")

	err := c.Validate(testLogger())
	require.NoError(t, err)

	_, err = c.NewDNSProvider()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment")
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
