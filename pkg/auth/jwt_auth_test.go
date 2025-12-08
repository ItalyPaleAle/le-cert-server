package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRoundTripper is a custom HTTP RoundTripper for mocking HTTP responses
type mockRoundTripper struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.handler != nil {
		return m.handler(req)
	}
	return &http.Response{
		StatusCode: 404,
		Body:       io.NopCloser(strings.NewReader("Not Found")),
	}, nil
}

// Helper function to create a test RSA key pair
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

// Helper function to create a JWK Set with a test key
func createTestJWKS(t *testing.T, kid string, publicKey *rsa.PublicKey) jwk.Set {
	key, err := jwk.Import(publicKey)
	require.NoError(t, err)

	err = key.Set(jwk.KeyIDKey, kid)
	require.NoError(t, err)
	err = key.Set(jwk.AlgorithmKey, jwa.RS256())
	require.NoError(t, err)
	err = key.Set(jwk.KeyUsageKey, "sig")
	require.NoError(t, err)

	set := jwk.NewSet()
	err = set.AddKey(key)
	require.NoError(t, err)

	return set
}

// Helper function to create a signed JWT token
func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims map[string]any) string {
	token := jwt.New()
	var err error

	// Set standard claims
	iss, ok := claims["iss"].(string)
	if ok {
		err = token.Set(jwt.IssuerKey, iss)
		require.NoError(t, err)
	}
	sub, ok := claims["sub"].(string)
	if ok {
		err = token.Set(jwt.SubjectKey, sub)
		require.NoError(t, err)
	}
	aud, ok := claims["aud"]
	if ok {
		err = token.Set(jwt.AudienceKey, aud)
		require.NoError(t, err)
	}

	// Set expiration (1 hour from now)
	err = token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	require.NoError(t, err)

	// Set issued at
	err = token.Set(jwt.IssuedAtKey, time.Now())
	require.NoError(t, err)

	// Set custom claims
	for k, v := range claims {
		if k != "iss" && k != "sub" && k != "aud" {
			err = token.Set(k, v)
			require.NoError(t, err)
		}
	}

	// Sign the token with the kid in the header
	hdrs := jws.NewHeaders()
	err = hdrs.Set(jws.KeyIDKey, kid)
	require.NoError(t, err)

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	return string(signedToken)
}

func TestAuthenticatorMiddleware(t *testing.T) {
	const (
		issuerURL = "https://auth.example.com"
		audience  = "test-audience"
		kid       = "test-key-1"
	)
	requiredScopes := []string{"read"}

	// Generate test keys
	privateKey, publicKey := generateTestKeyPair(t)
	jwks := createTestJWKS(t, kid, publicKey)

	// Marshal JWKS to JSON
	jwksJSON, err := json.Marshal(jwks)
	require.NoError(t, err)

	// Create mock responses
	discoveryResponse := OIDCDiscovery{
		Issuer:  issuerURL,
		JWKSURI: issuerURL + "/.well-known/jwks.json",
	}
	discoveryJSON, err := json.Marshal(discoveryResponse)
	require.NoError(t, err)

	// Setup mock HTTP client
	mockRT := &mockRoundTripper{
		handler: func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case issuerURL + "/.well-known/openid-configuration":
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader(discoveryJSON)),
				}, nil
			case issuerURL + "/.well-known/jwks.json":
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(bytes.NewReader(jwksJSON)),
				}, nil
			default:
				return &http.Response{
					StatusCode: 404,
					Body:       io.NopCloser(strings.NewReader("Not Found")),
				}, nil
			}
		},
	}

	// Create authenticator with mock client
	auth := &JWTAuthenticator{
		issuerURL:      issuerURL,
		audience:       audience,
		requiredScopes: requiredScopes,
		httpClient:     &http.Client{Transport: mockRT},
	}

	// Discover and refresh key set using mock client
	jwksURL, err := auth.discoverJWKS(t.Context())
	require.NoError(t, err)
	assert.Equal(t, issuerURL+"/.well-known/jwks.json", jwksURL)

	// Create a simple key set without using the cache
	keySet, err2 := jwk.Parse(jwksJSON)
	require.NoError(t, err2)
	auth.keySet = keySet

	tests := []struct {
		name           string
		authHeader     string
		tokenClaims    map[string]any
		expectedStatus int
		expectedUser   string
	}{
		{
			name:           "Missing Authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Authorization format",
			authHeader:     "InvalidFormat",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid Bearer format",
			authHeader:     "Basic dGVzdDp0ZXN0",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:       "Bearer prefix is case-insensitive",
			authHeader: "bearer %s",
			tokenClaims: map[string]any{
				"iss":   issuerURL,
				"sub":   "user123",
				"aud":   audience,
				"scope": "read write",
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "user123",
		},
		{
			name:       "Valid token with all required scopes",
			authHeader: "Bearer %s",
			tokenClaims: map[string]any{
				"iss":   issuerURL,
				"sub":   "user123",
				"aud":   audience,
				"scope": "read write",
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "user123",
		},
		{
			name:       "Valid token with scopes as array",
			authHeader: "Bearer %s",
			tokenClaims: map[string]any{
				"iss":    issuerURL,
				"sub":    "user456",
				"aud":    audience,
				"scopes": []string{"read", "write", "admin"},
			},
			expectedStatus: http.StatusOK,
			expectedUser:   "user456",
		},
		{
			name:       "Invalid issuer",
			authHeader: "Bearer %s",
			tokenClaims: map[string]any{
				"iss":   "https://wrong-issuer.com",
				"sub":   "user789",
				"aud":   audience,
				"scope": "read write",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid audience",
			authHeader: "Bearer %s",
			tokenClaims: map[string]any{
				"iss":   issuerURL,
				"sub":   "user999",
				"aud":   "wrong-audience",
				"scope": "read write",
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:       "Missing required scope",
			authHeader: "Bearer %s",
			tokenClaims: map[string]any{
				"iss":   issuerURL,
				"sub":   "user111",
				"aud":   audience,
				"scope": "write", // Missing "read" scope
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test handler
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify user context
				user, ok := GetUser(r.Context())
				if tt.expectedUser != "" && (!ok || tt.expectedUser != user) {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			handler := auth.Middleware(testHandler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set authorization header
			if tt.authHeader != "" {
				if tt.tokenClaims != nil {
					// Create and sign token
					token := createTestToken(t, privateKey, kid, tt.tokenClaims)
					req.Header.Set("Authorization", fmt.Sprintf(tt.authHeader, token))
				} else {
					req.Header.Set("Authorization", tt.authHeader)
				}
			}

			// Execute request
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify status code
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestValidateScopes(t *testing.T) {
	const (
		issuerURL = "https://auth.example.com"
		audience  = "test-audience"
	)

	// Create authenticator
	auth := &JWTAuthenticator{
		issuerURL:      issuerURL,
		audience:       audience,
		requiredScopes: []string{"read", "write"},
	}

	tests := []struct {
		name        string
		claims      map[string]any
		expectError bool
	}{
		{
			name: "Scopes as space-delimited string",
			claims: map[string]any{
				"scope": "read write admin",
			},
			expectError: false,
		},
		{
			name: "Scopes as array",
			claims: map[string]any{
				"scopes": []string{"read", "write", "admin"},
			},
			expectError: false,
		},
		{
			name: "Scopes as interface array",
			claims: map[string]any{
				"scopes": []any{"read", "write"},
			},
			expectError: false,
		},
		{
			name: "Missing required scope",
			claims: map[string]any{
				"scope": "read admin", // Missing "write"
			},
			expectError: true,
		},
		{
			name:        "No scope claim",
			claims:      map[string]any{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			for k, v := range tt.claims {
				err := token.Set(k, v)
				require.NoError(t, err)
			}

			err := auth.validateScopes(token)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetClaimFunctions(t *testing.T) {
	// Create a test token with various claims
	token := jwt.New()
	err := token.Set(jwt.SubjectKey, "user123")
	require.NoError(t, err)
	err = token.Set(jwt.IssuerKey, "https://auth.example.com")
	require.NoError(t, err)
	err = token.Set(jwt.AudienceKey, []string{"aud1", "aud2"})
	require.NoError(t, err)
	err = token.Set(jwt.JwtIDKey, "jwt-id-123")
	require.NoError(t, err)
	err = token.Set("custom_string", "custom_value")
	require.NoError(t, err)
	err = token.Set("custom_array", []string{"val1", "val2"})
	require.NoError(t, err)
	err = token.Set("custom_interface_array", []any{"val3", "val4"})
	require.NoError(t, err)

	// Create context with token
	ctx := t.Context()
	ctx = context.WithValue(ctx, claimsContextKey{}, token)
	ctx = context.WithValue(ctx, userContextKey{}, "user123")

	t.Run("GetUser", func(t *testing.T) {
		user, ok := GetUser(ctx)
		assert.True(t, ok)
		assert.Equal(t, "user123", user)

		// Test with empty context
		user, ok = GetUser(t.Context())
		assert.False(t, ok)
		assert.Empty(t, user)
	})

	t.Run("GetClaims", func(t *testing.T) {
		claims, ok := GetClaims(ctx)
		assert.True(t, ok)
		assert.NotNil(t, claims)

		// Test with empty context
		claims, ok = GetClaims(t.Context())
		assert.False(t, ok)
		assert.Nil(t, claims)
	})
}

func TestDiscoverJWKS(t *testing.T) {
	issuerURL := "https://auth.example.com"

	tests := []struct {
		name          string
		discoveryResp *OIDCDiscovery
		statusCode    int
		expectError   bool
		expectedJWKS  string
	}{
		{
			name: "Valid discovery",
			discoveryResp: &OIDCDiscovery{
				Issuer:  issuerURL,
				JWKSURI: "https://auth.example.com/jwks",
			},
			statusCode:   200,
			expectError:  false,
			expectedJWKS: "https://auth.example.com/jwks",
		},
		{
			name: "Missing JWKS URI",
			discoveryResp: &OIDCDiscovery{
				Issuer: issuerURL,
			},
			statusCode:  200,
			expectError: true,
		},
		{
			name:        "HTTP error",
			statusCode:  500,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.discoveryResp != nil {
				var err error
				body, err = json.Marshal(tt.discoveryResp)
				require.NoError(t, err)
			} else {
				body = []byte("error")
			}

			// Setup mock HTTP client
			mockRT := &mockRoundTripper{
				handler: func(req *http.Request) (*http.Response, error) {
					if req.URL.String() == "https://auth.example.com/.well-known/openid-configuration" {
						return &http.Response{
							StatusCode: tt.statusCode,
							Body:       io.NopCloser(bytes.NewBuffer(body)),
						}, nil
					}
					return &http.Response{
						StatusCode: 404,
						Body:       io.NopCloser(bytes.NewBufferString("Not Found")),
					}, nil
				},
			}

			auth := &JWTAuthenticator{
				issuerURL:  issuerURL,
				httpClient: &http.Client{Transport: mockRT},
			}

			jwksURL, err := auth.discoverJWKS(t.Context())
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedJWKS, jwksURL)
			}
		})
	}
}

func TestExpiredToken(t *testing.T) {
	issuerURL := "https://auth.example.com"
	audience := "test-audience"

	// Generate test keys
	privateKey, publicKey := generateTestKeyPair(t)
	kid := "test-key-1"
	jwks := createTestJWKS(t, kid, publicKey)

	// Create authenticator with mocked JWKS
	auth := &JWTAuthenticator{
		issuerURL: issuerURL,
		audience:  audience,
		keySet:    jwks,
	}

	// Create an expired token
	token := jwt.New()
	err := token.Set(jwt.IssuerKey, issuerURL)
	require.NoError(t, err)
	err = token.Set(jwt.SubjectKey, "user123")
	require.NoError(t, err)
	err = token.Set(jwt.AudienceKey, audience)
	require.NoError(t, err)
	err = token.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour)) // Expired 1 hour ago
	require.NoError(t, err)
	err = token.Set(jwt.IssuedAtKey, time.Now().Add(-2*time.Hour))
	require.NoError(t, err)

	// Sign the token with the kid in the header
	hdrs := jws.NewHeaders()
	err = hdrs.Set(jws.KeyIDKey, kid)
	require.NoError(t, err)

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), privateKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	// Validate should fail due to expiration
	_, err = auth.validateToken(t.Context(), string(signedToken))
	require.Error(t, err)
	require.ErrorContains(t, err, "exp")
}
