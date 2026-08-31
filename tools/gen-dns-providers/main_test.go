package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestCommonEnvPrefix(t *testing.T) {
	tests := []struct {
		name string
		envs []string
		want string
	}{
		{"single name", []string{"LIQUID_WEB_URL"}, "LIQUID_WEB_"},
		{"multi word namespace", []string{"LIQUID_WEB_URL", "LIQUID_WEB_USERNAME", "LIQUID_WEB_TTL"}, "LIQUID_WEB_"},
		// The shared prefix runs into the middle of a segment, which must be trimmed back
		{"partial segment trimmed", []string{"LWAPI_URL", "LWAPI_USERNAME"}, "LWAPI_"},
		{"no shared segment", []string{"OS_AUTH_URL", "TF_VAR_region"}, ""},
		{"no underscore", []string{"GANDIV5", "GANDIV5"}, ""},
		{"empty", nil, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := commonEnvPrefix(tc.envs)
			if got != tc.want {
				t.Errorf("commonEnvPrefix(%v) = %q, want %q", tc.envs, got, tc.want)
			}
		})
	}
}

// parseFuncDecl compiles a standalone function from source so the AST helpers can be exercised on realistic lego code
func parseFuncDecl(t *testing.T, src string) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "src.go", "package p\n"+src, 0)
	if err != nil {
		t.Fatalf("failed to parse test source: %v", err)
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if ok {
			return fd
		}
	}
	t.Fatal("test source has no function declaration")
	return nil
}

func TestCollectFieldEnv(t *testing.T) {
	consts := map[string]string{
		"EnvAPIKey":   "PDNS_API_KEY",
		"EnvAPIURL":   "PDNS_API_URL",
		"EnvEndpoint": "VERSIO_ENDPOINT",
	}
	configFields := map[string]string{
		"APIKey":  "string",
		"Host":    "*url.URL",
		"BaseURL": "*url.URL",
	}

	tests := []struct {
		name string
		src  string
		want map[string]string
	}{
		{
			name: "direct assignment",
			src:  "func f() { config.APIKey = values[EnvAPIKey] }",
			want: map[string]string{"APIKey": "PDNS_API_KEY"},
		},
		{
			// lego reads the env var into a local first, so the field must be traced back through it
			name: "assignment through a local variable",
			src:  "func f() { hostURL, err := url.Parse(values[EnvAPIURL]); _ = err; config.Host = hostURL }",
			want: map[string]string{"Host": "PDNS_API_URL"},
		},
		{
			name: "composite literal through a local variable",
			src:  "func f() { baseURL, _ := url.Parse(env.GetOrDefaultString(EnvEndpoint, d)); return &Config{BaseURL: baseURL} }",
			want: map[string]string{"BaseURL": "VERSIO_ENDPOINT"},
		},
		{
			name: "no env var involved",
			src:  "func f() { config.APIKey = defaultAPIKey }",
			want: map[string]string{},
		},
		{
			// A field that is not on the Config struct must never be recorded
			name: "unknown field ignored",
			src:  "func f() { client.Something = values[EnvAPIKey] }",
			want: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := make(map[string]string)
			collectFieldEnv(parseFuncDecl(t, tc.src), consts, configFields, got)

			if len(got) != len(tc.want) {
				t.Fatalf("collectFieldEnv returned %v, want %v", got, tc.want)
			}
			for field, env := range tc.want {
				if got[field] != env {
					t.Errorf("collectFieldEnv[%q] = %q, want %q", field, got[field], env)
				}
			}
		})
	}
}

// TestCollectFieldEnv_FirstAssignmentWins verifies that a later assignment does not override an earlier one
// lego providers often set a default in NewDefaultConfig and then overwrite it, and the first env var found is the authoritative one
func TestCollectFieldEnv_FirstAssignmentWins(t *testing.T) {
	consts := map[string]string{"EnvAPIKey": "PDNS_API_KEY", "EnvAPIURL": "PDNS_API_URL"}
	configFields := map[string]string{"APIKey": "string"}

	got := make(map[string]string)
	collectFieldEnv(parseFuncDecl(t, "func f() { config.APIKey = values[EnvAPIKey]; config.APIKey = values[EnvAPIURL] }"), consts, configFields, got)

	if got["APIKey"] != "PDNS_API_KEY" {
		t.Errorf("collectFieldEnv[\"APIKey\"] = %q, want %q", got["APIKey"], "PDNS_API_KEY")
	}
}

func TestValidateUnsupportedProviders(t *testing.T) {
	providers := []provider{{Code: "cloudflare"}, {Code: "plesk"}}

	tests := []struct {
		name        string
		unsupported []string
		wantErr     string
	}{
		{"known provider", []string{"plesk"}, ""},
		{"empty list", nil, ""},
		// A code lego does not have means the entry excludes nothing, which must not pass silently
		{"unknown provider", []string{"not-a-provider"}, "not a known lego provider"},
		{"duplicate entry", []string{"plesk", "plesk"}, "more than once"},
		{"empty entry", []string{""}, "empty entry"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUnsupportedProviders(tc.unsupported, providers)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateUnsupportedProviders(%v) returned an unexpected error: %v", tc.unsupported, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateUnsupportedProviders(%v) returned no error, want one containing %q", tc.unsupported, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("validateUnsupportedProviders(%v) error = %q, want it to contain %q", tc.unsupported, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestExcludeUnsupported(t *testing.T) {
	providers := []provider{{Code: "cloudflare"}, {Code: "plesk"}, {Code: "route53"}, {Code: "selfhostde"}}

	got := excludeUnsupported(providers, []string{"plesk", "selfhostde"})

	want := []string{"cloudflare", "route53"}
	if len(got) != len(want) {
		t.Fatalf("excludeUnsupported returned %d providers, want %d", len(got), len(want))
	}
	for i, code := range want {
		if got[i].Code != code {
			t.Errorf("excludeUnsupported()[%d].Code = %q, want %q", i, got[i].Code, code)
		}
	}
}

func TestConvFor(t *testing.T) {
	tests := []struct {
		typ  string
		want string
	}{
		{"string", "string"},
		{"int", "int"},
		{"int32", "int32"},
		{"int64", "int64"},
		{"bool", "bool"},
		{"time.Duration", "duration"},
		{"*url.URL", "url"},
		{"[]string", "stringslice"},
		{"map[string]string", "pairs"},
		{"cloud.Configuration", "azureenv"},
		// Types that cannot be built from a configuration string
		{"map[string]*Seq", ""},
		{"common.ConfigurationProvider", ""},
		{"*http.Client", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.typ, func(t *testing.T) {
			got := convFor(tc.typ)
			if got != tc.want {
				t.Errorf("convFor(%q) = %q, want %q", tc.typ, got, tc.want)
			}
		})
	}
}
