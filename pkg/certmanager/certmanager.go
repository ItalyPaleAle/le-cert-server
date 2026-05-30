package certmanager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"golang.org/x/sync/singleflight"

	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/storage"
)

// ErrRenewTooSoon is returned when a renewal is requested for a certificate that is not yet due for renewal
// It guards the manual renewal endpoint against wasting Let's Encrypt rate limits on redundant requests
var ErrRenewTooSoon = errors.New("certificate not yet due for renewal")

// CertManager handles certificate acquisition and renewal
type CertManager interface {
	ObtainCertificate(ctx context.Context, domain string) (cert *storage.Certificate, cached bool, err error)
	RenewCertificate(ctx context.Context, domain string) (*storage.Certificate, error)
	RenewExpiringCertificates(ctx context.Context) error
}

// certManager is the internal implementation of the CertManager interface
type certManager struct {
	storage    *storage.Storage
	appMetrics *metrics.AppMetrics

	// Collapses concurrent obtain/renew operations for the same domain into a single ACME call
	// Without this, multiple nodes requesting the same uncached certificate at once would each start an independent ACME order, racing on the DNS-01 challenge record and exhausting Let's Encrypt rate limits
	group singleflight.Group
}

// obtainResult is the value shared between callers collapsed by the singleflight group
type obtainResult struct {
	cert   *storage.Certificate
	cached bool
}

// NewCertManager creates a new certificate manager
func NewCertManager(store *storage.Storage, appMetrics *metrics.AppMetrics) CertManager {
	return &certManager{
		storage:    store,
		appMetrics: appMetrics,
	}
}

// User implements the lego registration.User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// getOrCreateUser gets or creates a Let's Encrypt user
func (cm *certManager) getOrCreateUser(ctx context.Context) (*User, error) {
	cfg := config.Get()

	// Try to load existing credentials
	creds, err := cm.storage.GetLECredentials(ctx, cfg.LetsEncrypt.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get Let's Encrypt credentials: %w", err)
	}

	var privateKey crypto.PrivateKey

	if creds != nil {
		// Parse existing key
		block, _ := pem.Decode(creds.Key)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}

		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	} else {
		// Generate new key
		privateKey, err = cm.generateNewKey(ctx, cfg.LetsEncrypt.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to generate LE key: %w", err)
		}
	}

	user := &User{
		Email: cfg.LetsEncrypt.Email,
		key:   privateKey,
	}

	return user, nil
}

func (cm *certManager) generateNewKey(ctx context.Context, email string) (privateKey crypto.PrivateKey, err error) {
	// Generate new key
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Save the key using PKCS#8 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	newCreds := &storage.LECredentials{
		Email:   email,
		KeyType: "P256",
		Key:     keyPEM,
	}

	err = cm.storage.SaveLECredentials(ctx, newCreds)
	if err != nil {
		return nil, fmt.Errorf("failed to save LE credentials: %w", err)
	}

	return privateKey, nil
}

// createLegoClient creates a lego ACME client
func (cm *certManager) createLegoClient(user *User) (*lego.Client, error) {
	cfg := config.Get()

	legoConfig := lego.NewConfig(user)
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	// Use staging or production
	if cfg.LetsEncrypt.Staging {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	} else {
		legoConfig.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Register if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to register: %w", err)
		}
		user.Registration = reg
	}

	// Configure DNS provider
	provider, err := cm.createDNSProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider: %w", err)
	}

	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	return client, nil
}

// ObtainCertificate obtains a new certificate for the specified domain
// Concurrent calls for the same domain are collapsed into a single ACME order
func (cm *certManager) ObtainCertificate(ctx context.Context, domain string) (*storage.Certificate, bool, error) {
	res, err, _ := cm.group.Do("obtain:"+domain, func() (any, error) {
		cert, cached, innerErr := cm.obtainCertificate(ctx, domain)
		if innerErr != nil {
			return nil, innerErr
		}
		return obtainResult{cert: cert, cached: cached}, nil
	})
	if err != nil {
		//nolint:wrapcheck
		return nil, false, err
	}

	result, _ := res.(obtainResult)
	return result.cert, result.cached, nil
}

// obtainCertificate performs the actual work of obtaining a certificate
func (cm *certManager) obtainCertificate(ctx context.Context, domain string) (cert *storage.Certificate, cached bool, err error) {
	cfg := config.Get()

	// Check if we already have a valid certificate
	cert, err = cm.storage.GetCertificate(ctx, domain)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check existing certificate: %w", err)
	}

	if cert != nil && time.Until(cert.NotAfter) > time.Duration(cfg.LetsEncrypt.RenewalDays)*24*time.Hour {
		// Certificate is still valid
		return cert, true, nil
	}

	// Get or create user
	user, err := cm.getOrCreateUser(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego client
	client, err := cm.createLegoClient(user)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create client: %w", err)
	}

	// Generate P256 ECDSA private key for the certificate
	certificatePrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate certificate private key: %w", err)
	}

	// Request certificate
	start := time.Now()

	request := certificate.ObtainRequest{
		Domains:    []string{domain},
		Bundle:     true,
		PrivateKey: certificatePrivateKey,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, false, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	cm.appMetrics.RecordLetsEncryptRequests(time.Since(start))

	// Parse the certificate to get validity dates
	block, _ := pem.Decode(certificates.Certificate)
	if block == nil {
		return nil, false, errors.New("failed to decode certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Save to database
	newCert := &storage.Certificate{
		Domain:      domain,
		Certificate: certificates.Certificate,
		PrivateKey:  certificates.PrivateKey,
		IssuerCert:  certificates.IssuerCertificate,
		NotBefore:   x509Cert.NotBefore,
		NotAfter:    x509Cert.NotAfter,
	}

	err = cm.storage.SaveCertificate(ctx, newCert)
	if err != nil {
		return nil, false, fmt.Errorf("failed to save certificate: %w", err)
	}

	return newCert, false, nil
}

// RenewCertificate renews an existing certificate
// Concurrent calls for the same domain are collapsed into a single ACME order
func (cm *certManager) RenewCertificate(ctx context.Context, domain string) (*storage.Certificate, error) {
	res, err, _ := cm.group.Do("renew:"+domain, func() (any, error) {
		return cm.renewCertificate(ctx, domain)
	})
	if err != nil {
		//nolint:wrapcheck
		return nil, err
	}

	cert, _ := res.(*storage.Certificate)
	return cert, nil
}

// renewCertificate performs the actual work of renewing a certificate
func (cm *certManager) renewCertificate(ctx context.Context, domain string) (*storage.Certificate, error) {
	// Get existing certificate
	cert, err := cm.storage.GetCertificate(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert == nil {
		return nil, fmt.Errorf("certificate not found for domain '%s'", domain)
	}

	// Refuse to renew a certificate that is not yet due for renewal
	// This prevents a misbehaving client from looping on the renew endpoint and exhausting Let's Encrypt rate limits
	cfg := config.Get()
	if time.Until(cert.NotAfter) > time.Duration(cfg.LetsEncrypt.RenewalDays)*24*time.Hour {
		return nil, fmt.Errorf("%w: certificate for domain '%s' is valid until %s and is only renewed within %d days of expiry", ErrRenewTooSoon, domain, cert.NotAfter.Format(time.RFC3339), cfg.LetsEncrypt.RenewalDays)
	}

	// Get or create user
	user, err := cm.getOrCreateUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego client
	client, err := cm.createLegoClient(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Renew certificate
	start := time.Now()

	certResource := certificate.Resource{
		Domain:            domain,
		Certificate:       cert.Certificate,
		PrivateKey:        cert.PrivateKey,
		IssuerCertificate: cert.IssuerCert,
	}

	certificates, err := client.Certificate.RenewWithOptions(certResource, &certificate.RenewOptions{
		Bundle: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	cm.appMetrics.RecordLetsEncryptRequests(time.Since(start))

	// Parse the certificate to get validity dates
	block, _ := pem.Decode(certificates.Certificate)
	if block == nil {
		return nil, errors.New("failed to decode certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Update in database
	cert.Certificate = certificates.Certificate
	cert.PrivateKey = certificates.PrivateKey
	cert.IssuerCert = certificates.IssuerCertificate
	cert.NotBefore = x509Cert.NotBefore
	cert.NotAfter = x509Cert.NotAfter

	err = cm.storage.SaveCertificate(ctx, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	return cert, nil
}

// RenewExpiringCertificates renews all certificates expiring soon
func (cm *certManager) RenewExpiringCertificates(ctx context.Context) error {
	cfg := config.Get()

	certs, err := cm.storage.GetExpiringCertificates(ctx, cfg.LetsEncrypt.RenewalDays)
	if err != nil {
		return fmt.Errorf("failed to get expiring certificates: %w", err)
	}

	slog.Info("Checking expiring certificates", "count", len(certs), "threshold_days", cfg.LetsEncrypt.RenewalDays)

	for _, cert := range certs {
		domainLogger := slog.With("domain", cert.Domain)
		domainLogger.Info("Renewing certificate", "expires", cert.NotAfter)

		_, err = cm.RenewCertificate(ctx, cert.Domain)
		if err != nil {
			// Log error but continue with other certificates
			domainLogger.Error("Failed to renew certificate", "error", err)
			continue
		}

		domainLogger.Info("Successfully renewed certificate")
	}

	return nil
}
