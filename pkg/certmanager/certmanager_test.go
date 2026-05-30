package certmanager

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/le-cert-server/pkg/storage"
)

// newTestManager creates a certManager backed by an in-memory SQLite storage
// The database name is derived from the test name so concurrent tests stay isolated
// The default global config sets LetsEncrypt.RenewalDays to 30, which these tests rely on
func newTestManager(t *testing.T) (*certManager, *storage.Storage) {
	t.Helper()

	dbName := strings.ReplaceAll(t.Name(), "/", "_")
	store, err := storage.NewStorage("file:" + dbName + "?mode=memory&cache=shared")
	require.NoError(t, err)

	err = store.Init(t.Context())
	require.NoError(t, err)

	cm := &certManager{storage: store}
	return cm, store
}

// testCertificate returns a certificate valid for the given duration from now
func testCertificate(domain string, validFor time.Duration) *storage.Certificate {
	now := time.Now().UTC().Truncate(time.Second)
	return &storage.Certificate{
		Domain:      domain,
		Certificate: []byte("CERT-" + domain),
		PrivateKey:  []byte("KEY-" + domain),
		IssuerCert:  []byte("ISSUER-" + domain),
		NotBefore:   now,
		NotAfter:    now.Add(validFor),
	}
}

// TestObtainCertificate_ReturnsCachedWhenValid verifies that a still-valid certificate
// is returned from storage without contacting Let's Encrypt
func TestObtainCertificate_ReturnsCachedWhenValid(t *testing.T) {
	cm, store := newTestManager(t)

	// A certificate that expires well beyond the 30-day renewal threshold
	err := store.SaveCertificate(t.Context(), testCertificate("example.com", 60*24*time.Hour))
	require.NoError(t, err)

	cert, cached, err := cm.ObtainCertificate(t.Context(), "example.com")

	require.NoError(t, err)
	assert.True(t, cached)
	require.NotNil(t, cert)
	assert.Equal(t, "example.com", cert.Domain)
}

// TestRenewCertificate_NotFound verifies renewing an unknown domain returns an error
// that is not the "too soon" guard
func TestRenewCertificate_NotFound(t *testing.T) {
	cm, _ := newTestManager(t)

	cert, err := cm.RenewCertificate(t.Context(), "missing.example.com")

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.NotErrorIs(t, err, ErrRenewTooSoon)
}

// TestRenewCertificate_TooSoon verifies that renewing a certificate that is not yet
// due for renewal is refused with ErrRenewTooSoon, before any Let's Encrypt call
func TestRenewCertificate_TooSoon(t *testing.T) {
	cm, store := newTestManager(t)

	// A fresh certificate, far from the 30-day renewal threshold
	err := store.SaveCertificate(t.Context(), testCertificate("example.com", 60*24*time.Hour))
	require.NoError(t, err)

	cert, err := cm.RenewCertificate(t.Context(), "example.com")

	require.Error(t, err)
	assert.Nil(t, cert)
	assert.ErrorIs(t, err, ErrRenewTooSoon)
}
