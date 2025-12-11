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

	"github.com/italypaleale/le-cert-server/pkg/config"
	"github.com/italypaleale/le-cert-server/pkg/metrics"
	"github.com/italypaleale/le-cert-server/pkg/storage"
)

// CertManager handles certificate acquisition and renewal
type CertManager struct {
	storage    *storage.Storage
	appMetrics *metrics.AppMetrics
}

// NewCertManager creates a new certificate manager
func NewCertManager(store *storage.Storage, appMetrics *metrics.AppMetrics) *CertManager {
	return &CertManager{
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
func (cm *CertManager) getOrCreateUser(ctx context.Context) (*User, error) {
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

func (cm *CertManager) generateNewKey(ctx context.Context, email string) (privateKey crypto.PrivateKey, err error) {
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
func (cm *CertManager) createLegoClient(user *User) (*lego.Client, error) {
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
func (cm *CertManager) ObtainCertificate(ctx context.Context, domain string) (cert *storage.Certificate, cached bool, err error) {
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
func (cm *CertManager) RenewCertificate(ctx context.Context, domain string) (*storage.Certificate, error) {
	// Get existing certificate
	cert, err := cm.storage.GetCertificate(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert == nil {
		return nil, fmt.Errorf("certificate not found for domain '%s'", domain)
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
func (cm *CertManager) RenewExpiringCertificates(ctx context.Context) error {
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
