package storage

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStorage creates a Storage backed by an in-memory SQLite database with migrations applied
// The database name is derived from the test name so concurrent tests stay isolated
func newTestStorage(t *testing.T) *Storage {
	t.Helper()

	dbName := strings.ReplaceAll(t.Name(), "/", "_")
	store, err := NewStorage("file:" + dbName + "?mode=memory&cache=shared")
	require.NoError(t, err)

	err = store.Init(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = store.db.Close()
	})

	return store
}

// testCertificate returns a certificate valid for the given duration from now
// Times are truncated to whole seconds (like real x509 certificates) so the
// not_after generated column parses cleanly via unixepoch
func testCertificate(domain string, validFor time.Duration) *Certificate {
	now := time.Now().UTC().Truncate(time.Second)
	return &Certificate{
		Domain:      domain,
		Certificate: []byte("CERT-" + domain),
		PrivateKey:  []byte("KEY-" + domain),
		IssuerCert:  []byte("ISSUER-" + domain),
		NotBefore:   now,
		NotAfter:    now.Add(validFor),
	}
}

func TestSaveAndGetCertificate(t *testing.T) {
	store := newTestStorage(t)

	cert := testCertificate("example.com", 60*24*time.Hour)
	err := store.SaveCertificate(t.Context(), cert)
	require.NoError(t, err)
	assert.NotZero(t, cert.ID)

	got, err := store.GetCertificate(t.Context(), "example.com")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "example.com", got.Domain)
	assert.Equal(t, []byte("CERT-example.com"), got.Certificate)
	assert.Equal(t, []byte("KEY-example.com"), got.PrivateKey)
	assert.Equal(t, []byte("ISSUER-example.com"), got.IssuerCert)
	assert.True(t, cert.NotAfter.Equal(got.NotAfter))
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestGetCertificate_NotFound(t *testing.T) {
	store := newTestStorage(t)

	got, err := store.GetCertificate(t.Context(), "missing.example.com")

	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestSaveCertificate_Upsert(t *testing.T) {
	store := newTestStorage(t)

	err := store.SaveCertificate(t.Context(), testCertificate("example.com", 10*24*time.Hour))
	require.NoError(t, err)

	// Save again for the same domain with different content
	updated := testCertificate("example.com", 90*24*time.Hour)
	updated.Certificate = []byte("UPDATED-CERT")
	err = store.SaveCertificate(t.Context(), updated)
	require.NoError(t, err)

	got, err := store.GetCertificate(t.Context(), "example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, []byte("UPDATED-CERT"), got.Certificate)

	// There must be exactly one row for the domain (ON CONFLICT upsert, not insert)
	var count int
	err = store.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM certificates WHERE domain = ?`, "example.com").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGetExpiringCertificates(t *testing.T) {
	store := newTestStorage(t)

	err := store.SaveCertificate(t.Context(), testCertificate("soon.example.com", 10*24*time.Hour))
	require.NoError(t, err)
	err = store.SaveCertificate(t.Context(), testCertificate("later.example.com", 90*24*time.Hour))
	require.NoError(t, err)

	// Within 30 days only "soon" should be returned
	certs, err := store.GetExpiringCertificates(t.Context(), 30)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "soon.example.com", certs[0].Domain)

	// Within 365 days both should be returned
	certs, err = store.GetExpiringCertificates(t.Context(), 365)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestSaveAndGetLECredentials(t *testing.T) {
	store := newTestStorage(t)

	creds := &LECredentials{
		Email:   "admin@example.com",
		KeyType: "P256",
		Key:     []byte("PRIVATE-KEY"),
	}
	err := store.SaveLECredentials(t.Context(), creds)
	require.NoError(t, err)
	assert.NotZero(t, creds.ID)

	got, err := store.GetLECredentials(t.Context(), "admin@example.com")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "admin@example.com", got.Email)
	assert.Equal(t, "P256", got.KeyType)
	assert.Equal(t, []byte("PRIVATE-KEY"), got.Key)
}

func TestGetLECredentials_NotFound(t *testing.T) {
	store := newTestStorage(t)

	got, err := store.GetLECredentials(t.Context(), "missing@example.com")

	require.NoError(t, err)
	assert.Nil(t, got)
}
