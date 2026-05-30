package auth

import (
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// PSKAuthenticator handles pre-shared key authentication
type PSKAuthenticator struct {
	preSharedKey []byte
}

// NewPSKAuthenticator creates a new pre-shared key authenticator
func NewPSKAuthenticator(preSharedKey string) (*PSKAuthenticator, error) {
	if preSharedKey == "" {
		return nil, errors.New("pre-shared key cannot be empty")
	}

	if len(preSharedKey) < 16 {
		return nil, errors.New("pre-shared key must be at least 16 characters long for security")
	}

	slog.Info("Initialized PSK authenticator")

	return &PSKAuthenticator{
		preSharedKey: []byte(preSharedKey),
	}, nil
}

// Middleware returns an HTTP middleware that validates pre-shared key authentication
func (a *PSKAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			slog.WarnContext(r.Context(), "Missing authorization header")
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check if it's an APIKey token
		const apiKeyPrefix = "apikey "
		if len(authHeader) <= len(apiKeyPrefix) || strings.ToLower(authHeader[:len(apiKeyPrefix)]) != apiKeyPrefix {
			slog.WarnContext(r.Context(), "Invalid authorization header format")
			http.Error(w, "Invalid Authorization header format (expected 'APIKey' prefix)", http.StatusUnauthorized)
			return
		}

		providedKey := authHeader[len(apiKeyPrefix):]

		// Validate the pre-shared key using constant-time comparison to prevent timing attacks
		if !a.validateKey(providedKey) {
			slog.WarnContext(r.Context(), "Invalid pre-shared key")
			http.Error(w, "Invalid authentication key", http.StatusUnauthorized)
			return
		}

		slog.DebugContext(r.Context(), "Authenticated request via PSK")

		// Key is valid, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// validateKey performs constant-time comparison of the provided key with the stored key
func (a *PSKAuthenticator) validateKey(providedKey string) bool {
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(providedKey), a.preSharedKey) == 1
}
