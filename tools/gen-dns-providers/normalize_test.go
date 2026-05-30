package main

import (
	"testing"
)

func TestBuildName(t *testing.T) {
	tests := []struct {
		env      string
		strip    bool
		wantGo   string
		wantYAML string
	}{
		{"CF_DNS_API_TOKEN", true, "DNSAPIToken", "dnsAPIToken"},
		{"AWS_ACCESS_KEY_ID", true, "AccessKeyID", "accessKeyID"},
		{"AZURE_CLIENT_CERTIFICATE_PATH", true, "ClientCertificatePath", "clientCertificatePath"},
		{"CF_API_EMAIL", true, "APIEmail", "apiEmail"},
		{"CLOUDFLARE_TTL", true, "TTL", "ttl"},
		{"CLOUDFLARE_BASE_URL", true, "BaseURL", "baseURL"},
		// Without stripping the provider prefix
		{"CF_DNS_API_TOKEN", false, "CfDNSAPIToken", "cfDNSAPIToken"},
		// Single-token key keeps its whole form
		{"GANDIV5", true, "Gandiv5", "gandiv5"},
	}

	for _, tc := range tests {
		t.Run(tc.env, func(t *testing.T) {
			gotGo, gotYAML := buildName(tc.env, tc.strip)
			if gotGo != tc.wantGo {
				t.Errorf("buildName(%q, %v) goName = %q, want %q", tc.env, tc.strip, gotGo, tc.wantGo)
			}
			if gotYAML != tc.wantYAML {
				t.Errorf("buildName(%q, %v) yamlName = %q, want %q", tc.env, tc.strip, gotYAML, tc.wantYAML)
			}
		})
	}
}

func TestNormalizeProvider_AliasMerge(t *testing.T) {
	credKeys := []string{"CF_API_EMAIL", "CF_DNS_API_TOKEN", "CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_EMAIL"}
	descs := map[string]string{
		"CF_API_EMAIL":             "Account email",
		"CF_DNS_API_TOKEN":         "API token with DNS:Edit permission",
		"CLOUDFLARE_DNS_API_TOKEN": "Alias to CF_DNS_API_TOKEN",
		"CLOUDFLARE_EMAIL":         "Alias to CF_API_EMAIL",
	}

	fields := normalizeProvider(credKeys, nil, descs)

	// The two aliases must fold into their target fields, not create new ones
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %+v", len(fields), fields)
	}

	byEnv := make(map[string]providerField)
	for _, f := range fields {
		byEnv[f.EnvVar] = f
	}

	email := byEnv["CF_API_EMAIL"]
	if email.YAMLName != "apiEmail" {
		t.Errorf("CF_API_EMAIL yaml = %q, want apiEmail", email.YAMLName)
	}
	if !contains(email.acceptedKeys(), "CLOUDFLARE_EMAIL") {
		t.Errorf("CF_API_EMAIL should accept alias CLOUDFLARE_EMAIL, got %v", email.acceptedKeys())
	}

	token := byEnv["CF_DNS_API_TOKEN"]
	if token.YAMLName != "dnsAPIToken" {
		t.Errorf("CF_DNS_API_TOKEN yaml = %q, want dnsAPIToken", token.YAMLName)
	}
	if !contains(token.acceptedKeys(), "CLOUDFLARE_DNS_API_TOKEN") {
		t.Errorf("CF_DNS_API_TOKEN should accept alias CLOUDFLARE_DNS_API_TOKEN, got %v", token.acceptedKeys())
	}
}

func TestNormalizeProvider_CollisionFallback(t *testing.T) {
	// Two keys with different prefixes that collide once the prefix is stripped
	credKeys := []string{"GANDI_API_KEY", "GANDIV5_API_KEY"}
	descs := map[string]string{
		"GANDI_API_KEY":   "Legacy API key",
		"GANDIV5_API_KEY": "v5 API key",
	}

	fields := normalizeProvider(credKeys, nil, descs)
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}

	// Because stripping the prefix collides on apiKey, the fallback keeps the prefix
	seen := make(map[string]bool)
	for _, f := range fields {
		if seen[f.YAMLName] {
			t.Errorf("duplicate yaml name %q after collision fallback", f.YAMLName)
		}
		seen[f.YAMLName] = true
	}
	if !seen["gandiAPIKey"] || !seen["gandiv5APIKey"] {
		t.Errorf("expected gandiAPIKey and gandiv5APIKey, got %v", seen)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
