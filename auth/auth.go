package auth

import (
	"context"
	"net/http"
	"strings"
)

// Authenticator handles authentication for the API
type Authenticator struct {
	bearerToken string
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(bearerToken string) *Authenticator {
	return &Authenticator{
		bearerToken: bearerToken,
	}
}

// Middleware returns an HTTP middleware that validates bearer tokens
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate the token
		if token != a.bearerToken {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const userContextKey contextKey = "user"

// WithUser adds user information to the request context
func WithUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// GetUser retrieves user information from the request context
func GetUser(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(userContextKey).(string)
	return user, ok
}
