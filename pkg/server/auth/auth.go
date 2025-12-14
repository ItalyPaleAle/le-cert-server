package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Authenticator is the interface that all authenticators must implement
type Authenticator interface {
	// Middleware returns an HTTP middleware that validates authentication
	Middleware(next http.Handler) http.Handler
}

type (
	userContextKey    struct{}
	domainsContextKey struct{}
	claimsContextKey  struct{}
)

// GetUser retrieves user information from the request context
func GetUser(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(userContextKey{}).(string)
	return user, ok
}

// GetDomains retrieves the list of allowed domains (if any) from the request context
func GetDomains(ctx context.Context) ([]string, bool) {
	domains, ok := ctx.Value(domainsContextKey{}).([]string)
	if ok && domains == nil {
		ok = false
	}
	return domains, ok
}

// GetClaims retrieves the full token from the request context
func GetClaims(ctx context.Context) (jwt.Token, bool) {
	token, ok := ctx.Value(claimsContextKey{}).(jwt.Token)
	return token, ok
}

// DomainAllowed returns true if the domain is allowed to the user
// If the authorization context contains a domain allowlist, the value must be present in the claim
// If the allowlist is not set or nil, then all domains are allowed
func DomainAllowed(ctx context.Context, domain string) bool {
	domains, ok := GetDomains(ctx)
	if !ok {
		// No allowlist, then everything is allowed
		return true
	}

	// Find the domain in the list
	for _, d := range domains {
		if d == "" {
			continue
		}
		switch {
		case d == "*":
			// Everything is allowed
			return true
		case d == domain:
			// Exact match
			return true
		case strings.HasPrefix(d, "*.") && strings.HasSuffix(domain, d[1:]):
			// Wildcard to include all sub-domains (e.g. "*.example.com"), so we allow if domain has suffix ".example.com"
			return true
		}
	}

	// If we're here, there was no match in the allowlist
	// (This also happens if the list was set but empty)
	return false
}
