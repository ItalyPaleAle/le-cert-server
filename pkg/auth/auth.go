package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Authenticator handles OAuth2/OIDC authentication for the API
type Authenticator struct {
	issuerURL      string
	audience       string
	requiredScopes []string
	jwksURL        string
	keySet         *JSONWebKeySet
	keySetMu       sync.RWMutex
}

// JSONWebKeySet represents a JWKS (JSON Web Key Set)
type JSONWebKeySet struct {
	Keys      []JSONWebKey
	ExpiresAt time.Time
}

// JSONWebKey represents a single key in a JWKS
type JSONWebKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// OIDCDiscovery represents the OIDC discovery document
type OIDCDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// NewAuthenticator creates a new OAuth2/OIDC authenticator
func NewAuthenticator(issuerURL, audience string, requiredScopes []string) (*Authenticator, error) {
	a := &Authenticator{
		issuerURL:      issuerURL,
		audience:       audience,
		requiredScopes: requiredScopes,
	}

	// Discover JWKS endpoint
	err := a.discoverJWKS()
	if err != nil {
		return nil, fmt.Errorf("failed to discover JWKS endpoint: %w", err)
	}

	// Fetch initial key set
	err = a.refreshKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch initial key set: %w", err)
	}

	// Start background refresh
	go a.startKeySetRefresh()

	return a, nil
}

// discoverJWKS discovers the JWKS endpoint from the OIDC discovery document
func (a *Authenticator) discoverJWKS() error {
	discoveryURL := strings.TrimSuffix(a.issuerURL, "/") + "/.well-known/openid-configuration"

	slog.Info("Discovering OIDC configuration", "url", discoveryURL)

	resp, err := http.Get(discoveryURL)
	if err != nil {
		return fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	if err != nil {
		return fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	if discovery.JWKSURI == "" {
		return errors.New("JWKS URI not found in discovery document")
	}

	a.jwksURL = discovery.JWKSURI
	slog.Info("Discovered JWKS endpoint", "url", a.jwksURL)

	return nil
}

// refreshKeySet fetches the JWKS from the issuer
func (a *Authenticator) refreshKeySet() error {
	slog.Debug("Refreshing JWKS key set", "url", a.jwksURL)

	resp, err := http.Get(a.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var keySet struct {
		Keys []JSONWebKey `json:"keys"`
	}

	err = json.NewDecoder(resp.Body).Decode(&keySet)
	if err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	a.keySetMu.Lock()
	a.keySet = &JSONWebKeySet{
		Keys:      keySet.Keys,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	a.keySetMu.Unlock()

	slog.Info("Refreshed JWKS key set", "keys", len(keySet.Keys))

	return nil
}

// startKeySetRefresh starts a background goroutine to refresh the key set
func (a *Authenticator) startKeySetRefresh() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	var err error
	for range ticker.C {
		err = a.refreshKeySet()
		if err != nil {
			slog.Error("Failed to refresh key set", "error", err)
		}
	}
}

// Middleware returns an HTTP middleware that validates OAuth2 bearer tokens
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			slog.Warn("Missing authorization header", "path", r.URL.Path)
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			slog.Warn("Invalid authorization header format", "path", r.URL.Path)
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Validate the token
		claims, err := a.validateToken(tokenString)
		if err != nil {
			slog.Warn("Token validation failed", "error", err, "path", r.URL.Path)
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, userContextKey, claims.Subject)
		ctx = context.WithValue(ctx, claimsContextKey, claims)

		slog.Info("Authenticated request", "subject", claims.Subject, "path", r.URL.Path)

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateToken validates a JWT token
func (a *Authenticator) validateToken(tokenString string) (*Claims, error) {
	// Parse token without validation first to get the kid
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" {
		return nil, fmt.Errorf("token missing kid header")
	}

	// Get the key from JWKS
	key, err := a.getKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Parse and validate token
	claims := &Claims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	// Validate issuer
	if claims.Issuer != a.issuerURL {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", a.issuerURL, claims.Issuer)
	}

	// Validate audience
	if !a.validateAudience(claims.Audience) {
		return nil, fmt.Errorf("invalid audience: %v", claims.Audience)
	}

	// Validate required scopes
	if len(a.requiredScopes) > 0 {
		if !a.validateScopes(claims.Scope) {
			return nil, fmt.Errorf("missing required scopes")
		}
	}

	return claims, nil
}

// validateAudience checks if the token audience is valid
func (a *Authenticator) validateAudience(tokenAud jwt.ClaimStrings) bool {
	return slices.Contains(tokenAud, a.audience)
}

// validateScopes checks if the token has all required scopes
func (a *Authenticator) validateScopes(tokenScope string) bool {
	tokenScopes := strings.Fields(tokenScope)
	tokenScopeMap := make(map[string]bool)
	for _, scope := range tokenScopes {
		tokenScopeMap[scope] = true
	}

	for _, required := range a.requiredScopes {
		if !tokenScopeMap[required] {
			return false
		}
	}

	return true
}

// getKey retrieves a key from the key set by kid
func (a *Authenticator) getKey(kid string) (any, error) {
	a.keySetMu.RLock()
	defer a.keySetMu.RUnlock()

	if a.keySet == nil {
		return nil, errors.New("key set not initialized")
	}

	// Check if key set is expired
	if time.Now().After(a.keySet.ExpiresAt) {
		// Try to refresh in background
		go func() {
			if err := a.refreshKeySet(); err != nil {
				slog.Error("Failed to refresh expired key set", "error", err)
			}
		}()
	}

	for _, key := range a.keySet.Keys {
		if key.Kid == kid {
			// For RSA keys with x5c (X.509 certificate chain)
			if len(key.X5c) > 0 {
				// Parse the first certificate in the chain
				return jwt.ParseRSAPublicKeyFromPEM([]byte("-----BEGIN CERTIFICATE-----\n" + key.X5c[0] + "\n-----END CERTIFICATE-----"))
			}
			// For other key types, you would need to implement additional parsing logic
			return nil, fmt.Errorf("unsupported key type for kid %s", kid)
		}
	}

	return nil, fmt.Errorf("key not found for kid %s", kid)
}

// Claims represents JWT claims
type Claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
}

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	userContextKey   contextKey = "user"
	claimsContextKey contextKey = "claims"
)

// GetUser retrieves user information from the request context
func GetUser(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(userContextKey).(string)
	return user, ok
}

// GetClaims retrieves the full claims from the request context
func GetClaims(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}
