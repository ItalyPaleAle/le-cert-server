package main

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// initialisms is the set of tokens that are upper-cased verbatim when building field names
// It is intentionally extensible: add tokens here when lego introduces env vars that should keep an all-caps form
var initialisms = map[string]bool{
	"API":   true,
	"ARN":   true,
	"BS":    true,
	"CA":    true,
	"CN":    true,
	"DDNS":  true,
	"DNS":   true,
	"DPF":   true,
	"DPM":   true,
	"GSS":   true,
	"HTTP":  true,
	"HTTPS": true,
	"IAM":   true,
	"ID":    true,
	"IP":    true,
	"JSON":  true,
	"MSI":   true,
	"OAUTH": true,
	"OCID":  true,
	"OTP":   true,
	"PDD":   true,
	"RAM":   true,
	"SAN":   true,
	"SDK":   true,
	"SSL":   true,
	"TLS":   true,
	"TSIG":  true,
	"TTL":   true,
	"URI":   true,
	"URL":   true,
	"UUID":  true,
	"VPC":   true,
	"WAPI":  true,
}

// aliasRegexp matches descriptions of the form "Alias to SOME_ENV_VAR"
var aliasRegexp = regexp.MustCompile(`(?i)^alias to\s+([A-Za-z0-9_]+)`)

// providerField describes a single credential or option for a DNS provider
type providerField struct {
	// GoName is the exported Go struct field name (e.g. DNSAPIToken)
	GoName string
	// YAMLName is the normalized YAML key (e.g. dnsAPIToken)
	YAMLName string
	// EnvVar is the canonical lego environment variable (e.g. CF_DNS_API_TOKEN)
	EnvVar string
	// Desc is the human-readable description from the lego TOML
	Desc string
	// Aliases are additional lego environment variables that map to this field
	Aliases []string
}

// acceptedKeys returns every YAML key that decodes into this field
// The order is normalized name, canonical env var, then sorted aliases
func (f providerField) acceptedKeys() []string {
	keys := []string{f.YAMLName, f.EnvVar}
	keys = append(keys, f.Aliases...)
	return keys
}

// goToken converts a single underscore-delimited token to its Go form
// Known initialisms are upper-cased verbatim; everything else is Title-cased
func goToken(tok string) string {
	if tok == "" {
		return ""
	}
	up := strings.ToUpper(tok)
	if initialisms[up] {
		return up
	}
	r := []rune(strings.ToLower(tok))
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// buildName derives the Go field name and YAML key for an environment variable
// When strip is true the first underscore-delimited segment (the provider prefix) is removed
func buildName(env string, strip bool) (goName string, yamlName string) {
	toks := strings.Split(env, "_")
	if strip && len(toks) > 1 {
		toks = toks[1:]
	}

	first := goToken(toks[0])
	var rest strings.Builder
	for _, t := range toks[1:] {
		rest.WriteString(goToken(t))
	}

	goName = first + rest.String()
	yamlName = strings.ToLower(first) + rest.String()
	return goName, yamlName
}

// normalizeProvider builds the ordered field list for a provider
// credKeys and addKeys must be the (sorted) Credentials and Additional env var names
// descs maps every env var name to its description
func normalizeProvider(credKeys []string, addKeys []string, descs map[string]string) []providerField {
	union := make([]string, 0, len(credKeys)+len(addKeys))
	union = append(union, credKeys...)
	union = append(union, addKeys...)

	// Detect aliases: a key whose description is "Alias to TARGET" is folded into TARGET's field
	isAlias := make(map[string]bool)
	aliasTargets := make(map[string][]string)
	for _, k := range union {
		m := aliasRegexp.FindStringSubmatch(descs[k])
		if m != nil {
			isAlias[k] = true
			target := m[1]
			aliasTargets[target] = append(aliasTargets[target], k)
		}
	}

	// Keep the non-alias keys in their original (sorted) order
	keys := make([]string, 0, len(union))
	for _, k := range union {
		if !isAlias[k] {
			keys = append(keys, k)
		}
	}

	// build constructs the fields for a given prefix-stripping mode and reports whether two keys collided
	build := func(strip bool) (fields []providerField, collision bool) {
		seen := make(map[string]string, len(keys))
		fields = make([]providerField, 0, len(keys))
		for _, k := range keys {
			goName, yamlName := buildName(k, strip)
			prev, ok := seen[yamlName]
			if ok && prev != k {
				collision = true
			}
			seen[yamlName] = k
			fields = append(fields, providerField{
				GoName:   goName,
				YAMLName: yamlName,
				EnvVar:   k,
				Desc:     descs[k],
			})
		}
		return fields, collision
	}

	// Try stripping the provider prefix first; fall back to keeping it if that causes a collision
	fields, collision := build(true)
	if collision {
		fields, _ = build(false)
	}

	// Attach aliases to their target fields
	for i := range fields {
		al := aliasTargets[fields[i].EnvVar]
		if len(al) > 0 {
			sort.Strings(al)
			fields[i].Aliases = al
		}
	}

	return fields
}
