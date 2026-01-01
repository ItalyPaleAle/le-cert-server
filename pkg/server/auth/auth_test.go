package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDomains_NoValueSet(t *testing.T) {
	ctx := t.Context()

	domains, ok := GetDomains(ctx)

	assert.False(t, ok)
	assert.Nil(t, domains)
}

func TestGetDomains_WithListOfDomains(t *testing.T) {
	expectedDomains := []string{"example.com", "test.com", "foo.bar"}
	ctx := context.WithValue(t.Context(), domainsContextKey{}, expectedDomains)

	domains, ok := GetDomains(ctx)

	assert.True(t, ok)
	assert.Equal(t, expectedDomains, domains)
	assert.Len(t, domains, 3)
}

func TestGetDomains_WithEmptyList(t *testing.T) {
	expectedDomains := []string{}
	ctx := context.WithValue(t.Context(), domainsContextKey{}, expectedDomains)

	domains, ok := GetDomains(ctx)

	assert.True(t, ok)
	assert.Equal(t, expectedDomains, domains)
	assert.Empty(t, domains)
}

func TestGetDomains_WithNullObject(t *testing.T) {
	var nilDomains []string
	ctx := context.WithValue(t.Context(), domainsContextKey{}, nilDomains)

	domains, ok := GetDomains(ctx)

	assert.False(t, ok)
	assert.Nil(t, domains)
}

func TestDomainAllowed_NoAllowlist(t *testing.T) {
	ctx := t.Context()

	// When no allowlist is set, all domains should be allowed
	assert.True(t, DomainAllowed(ctx, "example.com"))
	assert.True(t, DomainAllowed(ctx, "test.com"))
	assert.True(t, DomainAllowed(ctx, "any.domain.com"))
	assert.True(t, DomainAllowed(ctx, ""))
}

func TestDomainAllowed_EmptyAllowlist(t *testing.T) {
	ctx := context.WithValue(t.Context(), domainsContextKey{}, []string{})

	// When allowlist is empty, no domains should be allowed
	assert.False(t, DomainAllowed(ctx, "example.com"))
	assert.False(t, DomainAllowed(ctx, "test.com"))
	assert.False(t, DomainAllowed(ctx, "any.domain.com"))
}

func TestDomainAllowed_WildcardAllowlist(t *testing.T) {
	ctx := context.WithValue(t.Context(), domainsContextKey{}, []string{"*"})

	// When allowlist contains "*", all domains should be allowed
	assert.True(t, DomainAllowed(ctx, "example.com"))
	assert.True(t, DomainAllowed(ctx, "test.com"))
	assert.True(t, DomainAllowed(ctx, "any.domain.com"))
	assert.True(t, DomainAllowed(ctx, "sub.domain.example.com"))
}

func TestDomainAllowed_ExactMatch(t *testing.T) {
	ctx := context.WithValue(t.Context(), domainsContextKey{}, []string{
		"example.com",
		"test.com",
		"foo.bar.baz",
	})

	// Exact matches should be allowed
	assert.True(t, DomainAllowed(ctx, "example.com"))
	assert.True(t, DomainAllowed(ctx, "test.com"))
	assert.True(t, DomainAllowed(ctx, "foo.bar.baz"))

	// Non-matches should not be allowed
	assert.False(t, DomainAllowed(ctx, "notexample.com"))
	assert.False(t, DomainAllowed(ctx, "sub.example.com"))
	assert.False(t, DomainAllowed(ctx, "example.org"))
	assert.False(t, DomainAllowed(ctx, ""))
}

func TestDomainAllowed_WildcardSubdomain(t *testing.T) {
	ctx := context.WithValue(t.Context(), domainsContextKey{}, []string{
		"*.example.com",
		"*.test.org",
	})

	// Subdomains should be allowed
	assert.True(t, DomainAllowed(ctx, "sub.example.com"))
	assert.True(t, DomainAllowed(ctx, "www.example.com"))
	assert.True(t, DomainAllowed(ctx, "api.example.com"))
	assert.True(t, DomainAllowed(ctx, "deep.nested.example.com"))
	assert.True(t, DomainAllowed(ctx, "api.test.org"))

	// Base domain should NOT be allowed (no exact match)
	assert.False(t, DomainAllowed(ctx, "example.com"))
	assert.False(t, DomainAllowed(ctx, "test.org"))

	// Other domains should not be allowed
	assert.False(t, DomainAllowed(ctx, "example.org"))
	assert.False(t, DomainAllowed(ctx, "test.com"))
	assert.False(t, DomainAllowed(ctx, "notexample.com"))
}

func TestDomainAllowed_MixedAllowlist(t *testing.T) {
	ctx := context.WithValue(t.Context(), domainsContextKey{}, []string{
		"example.com",
		"*.test.org",
		"specific.domain.net",
	})

	// Exact matches
	assert.True(t, DomainAllowed(ctx, "example.com"))
	assert.True(t, DomainAllowed(ctx, "specific.domain.net"))

	// Wildcard matches
	assert.True(t, DomainAllowed(ctx, "sub.test.org"))
	assert.True(t, DomainAllowed(ctx, "www.test.org"))
	assert.True(t, DomainAllowed(ctx, "api.test.org"))

	// Non-matches
	assert.False(t, DomainAllowed(ctx, "test.org"))        // Base domain not in allowlist
	assert.False(t, DomainAllowed(ctx, "sub.example.com")) // No wildcard for example.com
	assert.False(t, DomainAllowed(ctx, "domain.net"))      // Not an exact match
	assert.False(t, DomainAllowed(ctx, "other.com"))
}

func TestDomainAllowed_EmptyStringsInAllowlist(t *testing.T) {
	ctx := context.WithValue(t.Context(), domainsContextKey{}, []string{
		"",
		"example.com",
		"",
		"test.com",
		"",
	})

	// Empty strings should be ignored, valid domains should match
	assert.True(t, DomainAllowed(ctx, "example.com"))
	assert.True(t, DomainAllowed(ctx, "test.com"))

	// Empty domain query should not match
	assert.False(t, DomainAllowed(ctx, ""))

	// Non-matches should not be allowed
	assert.False(t, DomainAllowed(ctx, "other.com"))
}

func TestDomainAllowed_NilAllowlist(t *testing.T) {
	var nilDomains []string
	ctx := context.WithValue(t.Context(), domainsContextKey{}, nilDomains)

	// Nil allowlist means it was set but is nil, so all domains should be allowed
	assert.True(t, DomainAllowed(ctx, "example.com"))
	assert.True(t, DomainAllowed(ctx, "test.com"))
	assert.True(t, DomainAllowed(ctx, "any.domain.com"))
}
