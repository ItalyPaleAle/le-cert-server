package config

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// validConfig returns a minimal Config that passes Validate (tcp listener + psk auth)
func validConfig() *Config {
	return &Config{
		Server: ConfigServer{
			Listener: "tcp",
			Bind:     "127.0.0.1",
		},
		LetsEncrypt: ConfigLetsEncrypt{
			Email:       "admin@example.com",
			DNSProvider: "cloudflare",
			RenewalDays: 30,
		},
		Auth: ConfigAuth{
			Method: "psk",
			PSK:    ConfigAuthPSK{Key: "this-is-a-long-enough-key"},
		},
	}
}

func TestValidate_ValidTCPPSK(t *testing.T) {
	c := validConfig()

	err := c.Validate(testLogger())

	require.NoError(t, err)
	// Port should be defaulted to 7401 in tcp mode
	assert.Equal(t, 7401, c.Server.Port)
}

func TestValidate_ValidJWT(t *testing.T) {
	c := validConfig()
	c.Auth = ConfigAuth{
		Method: "jwt",
		JWT: ConfigAuthJWT{
			IssuerURL: "https://issuer.example.com",
			Audience:  "my-audience",
		},
	}

	err := c.Validate(testLogger())

	require.NoError(t, err)
}

func TestValidate_TSNetDefaultsPort(t *testing.T) {
	c := validConfig()
	c.Server.Listener = "tsnet"
	c.Auth = ConfigAuth{Method: "tsnet"}

	err := c.Validate(testLogger())

	require.NoError(t, err)
	// Port should be defaulted to 443 in tsnet mode
	assert.Equal(t, 443, c.Server.Port)
}

func TestValidate_LowercasesListenerAndMethod(t *testing.T) {
	c := validConfig()
	c.Server.Listener = "TCP"
	c.Auth.Method = "PSK"

	err := c.Validate(testLogger())

	require.NoError(t, err)
	assert.Equal(t, "tcp", c.Server.Listener)
	assert.Equal(t, "psk", c.Auth.Method)
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"negative port", func(c *Config) { c.Server.Port = -1 }},
		{"missing email", func(c *Config) { c.LetsEncrypt.Email = "" }},
		{"missing dns provider", func(c *Config) { c.LetsEncrypt.DNSProvider = "" }},
		{"missing bind in tcp", func(c *Config) { c.Server.Bind = "" }},
		{"invalid listener", func(c *Config) { c.Server.Listener = "udp" }},
		{"psk empty", func(c *Config) { c.Auth.PSK.Key = "" }},
		{"psk too short", func(c *Config) { c.Auth.PSK.Key = "short" }},
		{"invalid auth method", func(c *Config) { c.Auth.Method = "basic" }},
		{"jwt missing issuer", func(c *Config) {
			c.Auth = ConfigAuth{Method: "jwt", JWT: ConfigAuthJWT{Audience: "aud"}}
		}},
		{"jwt missing audience", func(c *Config) {
			c.Auth = ConfigAuth{Method: "jwt", JWT: ConfigAuthJWT{IssuerURL: "https://issuer.example.com"}}
		}},
		{"tsnet auth requires tsnet listener", func(c *Config) {
			c.Server.Listener = "tcp"
			c.Auth = ConfigAuth{Method: "tsnet"}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)

			err := c.Validate(testLogger())

			assert.Error(t, err)
		})
	}
}
