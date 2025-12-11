package auth

import (
	"context"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Authenticator is the interface that all authenticators must implement
type Authenticator interface {
	// Middleware returns an HTTP middleware that validates authentication
	Middleware(next http.Handler) http.Handler
}

type (
	userContextKey   struct{}
	claimsContextKey struct{}
)

// GetUser retrieves user information from the request context
func GetUser(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(userContextKey{}).(string)
	return user, ok
}

// GetClaims retrieves the full token from the request context
func GetClaims(ctx context.Context) (jwt.Token, bool) {
	token, ok := ctx.Value(claimsContextKey{}).(jwt.Token)
	return token, ok
}
