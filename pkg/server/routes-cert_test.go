package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/italypaleale/le-cert-server/pkg/certmanager"
	"github.com/italypaleale/le-cert-server/pkg/storage"
)

// fakeManager is a stub CertManager for handler tests
type fakeManager struct {
	obtainCert   *storage.Certificate
	obtainCached bool
	obtainErr    error
	renewCert    *storage.Certificate
	renewErr     error
}

func (f *fakeManager) ObtainCertificate(_ context.Context, _ string) (*storage.Certificate, bool, error) {
	return f.obtainCert, f.obtainCached, f.obtainErr
}

func (f *fakeManager) RenewCertificate(_ context.Context, _ string) (*storage.Certificate, error) {
	return f.renewCert, f.renewErr
}

func (f *fakeManager) RenewExpiringCertificates(_ context.Context) error {
	return nil
}

func sampleCert() *storage.Certificate {
	now := time.Now().UTC().Truncate(time.Second)
	return &storage.Certificate{
		Domain:      "example.com",
		Certificate: []byte("CERT"),
		PrivateKey:  []byte("KEY"),
		IssuerCert:  []byte("ISSUER"),
		NotBefore:   now,
		NotAfter:    now.Add(90 * 24 * time.Hour),
	}
}

func doRequest(t *testing.T, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/certificate", strings.NewReader(body))
	w := httptest.NewRecorder()
	handler(w, r)
	return w
}

func TestHandleGetCertificate_InvalidBody(t *testing.T) {
	s := &Server{manager: &fakeManager{}}

	w := doRequest(t, s.handleGetCertificate, "{not-json")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetCertificate_MissingDomain(t *testing.T) {
	s := &Server{manager: &fakeManager{}}

	w := doRequest(t, s.handleGetCertificate, `{"domain": ""}`)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetCertificate_Success(t *testing.T) {
	s := &Server{manager: &fakeManager{obtainCert: sampleCert(), obtainCached: true}}

	w := doRequest(t, s.handleGetCertificate, `{"domain": "example.com"}`)

	require.Equal(t, http.StatusOK, w.Code)

	var resp CertificateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "example.com", resp.Domain)
	assert.Equal(t, "CERT", resp.Certificate)
	assert.Equal(t, "KEY", resp.PrivateKey)
	assert.True(t, resp.Cached)

	// Guard against the snake_case/camelCase drift noted in the review: the wire format is camelCase
	assert.Contains(t, w.Body.String(), `"privateKey"`)
	assert.NotContains(t, w.Body.String(), `"private_key"`)
}

func TestHandleGetCertificate_ManagerError(t *testing.T) {
	s := &Server{manager: &fakeManager{obtainErr: assert.AnError}}

	w := doRequest(t, s.handleGetCertificate, `{"domain": "example.com"}`)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleRenewCertificate_TooSoon(t *testing.T) {
	s := &Server{manager: &fakeManager{renewErr: certmanager.ErrRenewTooSoon}}

	w := doRequest(t, s.handleRenewCertificate, `{"domain": "example.com"}`)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestHandleRenewCertificate_Success(t *testing.T) {
	s := &Server{manager: &fakeManager{renewCert: sampleCert()}}

	w := doRequest(t, s.handleRenewCertificate, `{"domain": "example.com"}`)

	require.Equal(t, http.StatusOK, w.Code)

	var resp CertificateResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "example.com", resp.Domain)
	assert.False(t, resp.Cached)
}

func TestHandleRenewCertificate_ManagerError(t *testing.T) {
	s := &Server{manager: &fakeManager{renewErr: assert.AnError}}

	w := doRequest(t, s.handleRenewCertificate, `{"domain": "example.com"}`)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
