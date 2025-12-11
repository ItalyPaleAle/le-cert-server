package auth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/httprc/v3/errsink"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/spf13/cast"
)

// JWTAuthenticator handles OAuth2/OIDC authentication for the API
type JWTAuthenticator struct {
	issuerURL      string
	audience       string
	requiredScopes []string
	cache          *jwk.Cache
	keySet         jwk.Set
	httpClient     *http.Client
}

// OIDCDiscovery represents the OIDC discovery document
//
//nolint:tagliatelle
type OIDCDiscovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// NewJWTAuthenticator creates a new OAuth2/OIDC authenticator
func NewJWTAuthenticator(ctx context.Context, issuerURL, audience string, requiredScopes []string) (*JWTAuthenticator, error) {
	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	a := &JWTAuthenticator{
		issuerURL:      issuerURL,
		audience:       audience,
		requiredScopes: requiredScopes,
		httpClient:     httpClient,
	}

	// Discover JWKS endpoint from OIDC discovery
	jwksURL, err := a.discoverJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to discover JWKS endpoint: %w", err)
	}

	// Create JWK cache for automatic JWKS refreshing
	a.cache, err = jwk.NewCache(ctx, httprc.NewClient(
		httprc.WithHTTPClient(httpClient),
		httprc.WithErrorSink(errsink.NewSlog(slog.Default().With("scope", "jwkcache"))),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK cache: %w", err)
	}

	// Register the URL to fetch the JWKS from
	// The cache can dynamically decide how often to refresh the keyset based on the HTTP headers returned by the server, but the value must be at least 1 hour, and at most 7 days
	err = a.cache.Register(ctx,
		jwksURL,
		jwk.WithMaxInterval(7*24*time.Hour),
		jwk.WithMinInterval(15*time.Minute),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL with cache: %w", err)
	}

	// Refresh the key set initially to verify connectivity
	keySet, err := a.cache.Refresh(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
	}

	// Verify we have at least one key
	if keySet.Len() == 0 {
		return nil, errors.New("JWKS endpoint returned no keys")
	}

	// Create a CachedSet that always points at the latest JWKS in jwkCache
	// This implements jwk.Set and is kept up-to-date by the underlying httprc refresh loop
	a.keySet, err = a.cache.CachedSet(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get cached JWKS: %w", err)
	}

	slog.Info(
		"Initialized authenticator with cached JWKS",
		"issuer", issuerURL,
		"audience", audience,
		"jwksUrl", jwksURL,
	)

	return a, nil
}

// discoverJWKS discovers the JWKS endpoint from the OIDC discovery document
func (a *JWTAuthenticator) discoverJWKS(parentCtx context.Context) (string, error) {
	discoveryURL := strings.TrimSuffix(a.issuerURL, "/") + "/.well-known/openid-configuration"

	slog.Debug("Discovering OIDC configuration", slog.String("url", discoveryURL))

	ctx, cancel := context.WithTimeout(parentCtx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	if err != nil {
		return "", fmt.Errorf("failed to decode OIDC discovery document: %w", err)
	}

	if discovery.JWKSURI == "" {
		return "", errors.New("JWKS URI not found in discovery document")
	}

	slog.Debug("Discovered JWKS endpoint", "url", discovery.JWKSURI)

	return discovery.JWKSURI, nil
}

// Middleware returns an HTTP middleware that validates OAuth2 bearer tokens
func (a *JWTAuthenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			slog.Warn("Missing authorization header", slog.String("path", r.URL.Path))
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		const bearerPrefix = "bearer "
		if len(authHeader) <= len(bearerPrefix) || strings.ToLower(authHeader[:len(bearerPrefix)]) != bearerPrefix {
			slog.Warn("Invalid authorization header format", slog.String("path", r.URL.Path))
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[len(bearerPrefix):]

		// Validate the token
		token, err := a.validateToken(r.Context(), tokenString)
		if err != nil {
			slog.Warn("Token validation failed", slog.Any("error", err), slog.String("path", r.URL.Path))
			http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			return
		}

		// Extract subject
		subject, _ := token.Subject()

		// Add claims to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, userContextKey{}, subject)
		ctx = context.WithValue(ctx, claimsContextKey{}, token)

		slog.Debug("Authenticated request", slog.String("subject", subject), slog.String("path", r.URL.Path))

		// Token is valid, proceed to the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateToken validates a JWT token using jwx
func (a *JWTAuthenticator) validateToken(ctx context.Context, tokenString string) (jwt.Token, error) {
	// Parse and validate the token with the key set
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(a.keySet, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithVerify(true),
		jwt.WithIssuer(a.issuerURL),
		jwt.WithAudience(a.audience),
		jwt.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse/validate token: %w", err)
	}

	// Validate required scopes if configured
	if len(a.requiredScopes) > 0 {
		err = a.validateScopes(token)
		if err != nil {
			return nil, err
		}
	}

	return token, nil
}

// validateScopes checks if the token has all required scopes
func (a *JWTAuthenticator) validateScopes(token jwt.Token) error {
	// Get scope claim - it could be either a string or a slice
	var scopeValue any
	err := token.Get("scope", &scopeValue)
	if err != nil {
		// Try alternative claim name
		err = token.Get("scopes", &scopeValue)
		if err != nil {
			return errors.New("token missing scope claim")
		}
	}

	tokenScopes := cast.ToStringSlice(scopeValue)

	// Check if all required scopes are present
	for _, required := range a.requiredScopes {
		if !slices.Contains(tokenScopes, required) {
			return fmt.Errorf("missing required scope: %s", required)
		}
	}

	return nil
}
