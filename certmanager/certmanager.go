package certmanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/yourusername/cert-server/storage"
)

// CertManager handles certificate acquisition and renewal
type CertManager struct {
	storage     *storage.Storage
	email       string
	staging     bool
	dnsProvider string
	dnsCreds    map[string]string
	renewalDays int
	logger      *slog.Logger
}

// NewCertManager creates a new certificate manager
func NewCertManager(
	store *storage.Storage,
	email string,
	staging bool,
	dnsProvider string,
	dnsCreds map[string]string,
	renewalDays int,
	logger *slog.Logger,
) *CertManager {
	if logger == nil {
		logger = slog.Default()
	}

	return &CertManager{
		storage:     store,
		email:       email,
		staging:     staging,
		dnsProvider: dnsProvider,
		dnsCreds:    dnsCreds,
		renewalDays: renewalDays,
		logger:      logger,
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
func (cm *CertManager) getOrCreateUser() (*User, error) {
	// Try to load existing credentials
	creds, err := cm.storage.GetLECredentials(cm.email)
	if err != nil {
		return nil, fmt.Errorf("failed to get LE credentials: %w", err)
	}

	var privateKey crypto.PrivateKey

	if creds != nil {
		// Parse existing key
		block, _ := pem.Decode(creds.Key)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}

		// Try PKCS#8 first, then fall back to EC format for compatibility
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try EC format for backward compatibility
			privateKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
		}
	} else {
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
			Email:   cm.email,
			KeyType: "P256",
			Key:     keyPEM,
		}

		if err := cm.storage.SaveLECredentials(newCreds); err != nil {
			return nil, fmt.Errorf("failed to save LE credentials: %w", err)
		}
	}

	user := &User{
		Email: cm.email,
		key:   privateKey,
	}

	return user, nil
}

// createLegoClient creates a lego ACME client
func (cm *CertManager) createLegoClient(user *User) (*lego.Client, error) {
	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.RSA2048

	// Use staging or production
	if cm.staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	// Register if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
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

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("failed to set DNS provider: %w", err)
	}

	return client, nil
}

// ObtainCertificate obtains a new certificate for the specified domain
func (cm *CertManager) ObtainCertificate(domain string) (*storage.Certificate, error) {
	// Check if we already have a valid certificate
	cert, err := cm.storage.GetCertificate(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing certificate: %w", err)
	}

	if cert != nil && time.Until(cert.NotAfter) > time.Duration(cm.renewalDays)*24*time.Hour {
		// Certificate is still valid
		return cert, nil
	}

	// Get or create user
	user, err := cm.getOrCreateUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego client
	client, err := cm.createLegoClient(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Parse the certificate to get validity dates
	block, _ := pem.Decode(certificates.Certificate)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
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

	if err := cm.storage.SaveCertificate(newCert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	return newCert, nil
}

// RenewCertificate renews an existing certificate
func (cm *CertManager) RenewCertificate(domain string) (*storage.Certificate, error) {
	// Get existing certificate
	cert, err := cm.storage.GetCertificate(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	if cert == nil {
		return nil, fmt.Errorf("certificate not found for domain: %s", domain)
	}

	// Get or create user
	user, err := cm.getOrCreateUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego client
	client, err := cm.createLegoClient(user)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// Renew certificate
	certResource := certificate.Resource{
		Domain:            domain,
		Certificate:       cert.Certificate,
		PrivateKey:        cert.PrivateKey,
		IssuerCertificate: cert.IssuerCert,
	}

	certificates, err := client.Certificate.Renew(certResource, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %w", err)
	}

	// Parse the certificate to get validity dates
	block, _ := pem.Decode(certificates.Certificate)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
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

	err = cm.storage.SaveCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to save renewed certificate: %w", err)
	}

	return cert, nil
}

// RenewExpiringCertificates renews all certificates expiring soon
func (cm *CertManager) RenewExpiringCertificates() error {
	certs, err := cm.storage.GetExpiringCertificates(cm.renewalDays)
	if err != nil {
		return fmt.Errorf("failed to get expiring certificates: %w", err)
	}

	cm.logger.Info("Checking expiring certificates", "count", len(certs), "threshold_days", cm.renewalDays)

	for _, cert := range certs {
		domainLogger := cm.logger.With("domain", cert.Domain)
		domainLogger.Info("Renewing certificate", "expires", cert.NotAfter)
		_, err = cm.RenewCertificate(cert.Domain)
		if err != nil {
			// Log error but continue with other certificates
			domainLogger.Error("Failed to renew certificate", "error", err)
		} else {
			domainLogger.Info("Successfully renewed certificate")
		}
	}

	return nil
}
