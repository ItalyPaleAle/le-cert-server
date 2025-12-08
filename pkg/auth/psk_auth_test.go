package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPSKAuthenticator(t *testing.T) {
	tests := []struct {
		name        string
		psk         string
		expectError bool
	}{
		{
			name:        "Valid PSK",
			psk:         "this-is-a-very-secure-pre-shared-key-123456",
			expectError: false,
		},
		{
			name:        "Empty PSK",
			psk:         "",
			expectError: true,
		},
		{
			name:        "PSK too short",
			psk:         "short-key",
			expectError: true,
		},
		{
			name:        "PSK exactly 32 chars",
			psk:         "12345678901234567890123456789012",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewPSKAuthenticator(tt.psk)
			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, auth)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, auth)
				assert.Equal(t, tt.psk, auth.preSharedKey)
			}
		})
	}
}

func TestPSKAuthenticatorMiddleware(t *testing.T) {
	const testPSK = "this-is-a-very-secure-pre-shared-key-123456"

	auth, err := NewPSKAuthenticator(testPSK)
	require.NoError(t, err)

	tests := []struct {
		name           string
		authHeader     string
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
			authHeader:     "Bearer " + testPSK,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Valid PSK with lowercase apikey",
			authHeader:     "apikey " + testPSK,
			expectedStatus: http.StatusOK,
			expectedUser:   "psk-user",
		},
		{
			name:           "Valid PSK with uppercase APIKey",
			authHeader:     "APIKey " + testPSK,
			expectedStatus: http.StatusOK,
			expectedUser:   "psk-user",
		},
		{
			name:           "Valid PSK with mixed case ApiKey",
			authHeader:     "ApiKey " + testPSK,
			expectedStatus: http.StatusOK,
			expectedUser:   "psk-user",
		},
		{
			name:           "Invalid PSK",
			authHeader:     "APIKey wrong-key-that-is-still-long-enough",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "PSK with extra spaces",
			authHeader:     "APIKey  " + testPSK,
			expectedStatus: http.StatusUnauthorized, // Extra space makes it invalid
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
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Execute request
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Verify status code
			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestValidateKey(t *testing.T) {
	const testPSK = "this-is-a-very-secure-pre-shared-key-123456"

	auth, err := NewPSKAuthenticator(testPSK)
	require.NoError(t, err)

	tests := []struct {
		name     string
		key      string
		expected bool
	}{
		{
			name:     "Correct key",
			key:      testPSK,
			expected: true,
		},
		{
			name:     "Wrong key",
			key:      "this-is-a-wrong-pre-shared-key-1234567890",
			expected: false,
		},
		{
			name:     "Empty key",
			key:      "",
			expected: false,
		},
		{
			name:     "Key with similar prefix",
			key:      "this-is-a-very-secure-pre-shared-key-123457",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.validateKey(tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}