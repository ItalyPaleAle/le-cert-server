package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Storage handles certificate and credential persistence
type Storage struct {
	db *sql.DB
}

// Certificate represents a stored TLS certificate
type Certificate struct {
	ID          int64
	Domain      string
	Certificate []byte
	PrivateKey  []byte
	IssuerCert  []byte
	NotBefore   time.Time
	NotAfter    time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// LECredentials represents stored Let's Encrypt credentials
type LECredentials struct {
	ID        int64
	Email     string
	KeyType   string
	Key       []byte
	CreatedAt time.Time
	UpdatedAt time.Time
}

// DNSCredentials represents stored DNS provider credentials
type DNSCredentials struct {
	ID          int64
	Provider    string
	Credentials map[string]string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewStorage creates a new storage instance
func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &Storage{
		db: db,
	}
	err = storage.initialize()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return storage, nil
}

// initialize creates the database schema
func (s *Storage) initialize() error {
	const schema = `
	CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT UNIQUE NOT NULL,
		certificate BLOB NOT NULL,
		private_key BLOB NOT NULL,
		issuer_cert BLOB,
		not_before DATETIME NOT NULL,
		not_after DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain);
	CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);

	CREATE TABLE IF NOT EXISTS le_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		key_type TEXT NOT NULL,
		key BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.db.Close()
}

// SaveCertificate saves or updates a certificate
func (s *Storage) SaveCertificate(cert *Certificate) error {
	const query = `
	INSERT INTO certificates (domain, certificate, private_key, issuer_cert, not_before, not_after, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(domain) DO UPDATE SET
		certificate = excluded.certificate,
		private_key = excluded.private_key,
		issuer_cert = excluded.issuer_cert,
		not_before = excluded.not_before,
		not_after = excluded.not_after,
		updated_at = CURRENT_TIMESTAMP
	`

	result, err := s.db.Exec(query, cert.Domain, cert.Certificate, cert.PrivateKey, cert.IssuerCert, cert.NotBefore, cert.NotAfter)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	if cert.ID == 0 {
		id, err := result.LastInsertId()
		if err == nil {
			cert.ID = id
		}
	}

	return nil
}

// GetCertificate retrieves a certificate by domain
func (s *Storage) GetCertificate(domain string) (*Certificate, error) {
	const query = `
	SELECT id, domain, certificate, private_key, issuer_cert, not_before, not_after, created_at, updated_at
	FROM certificates
	WHERE domain = ?
	`

	cert := &Certificate{}
	err := s.db.
		QueryRow(query, domain).
		Scan(&cert.ID, &cert.Domain, &cert.Certificate, &cert.PrivateKey, &cert.IssuerCert, &cert.NotBefore, &cert.NotAfter, &cert.CreatedAt, &cert.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return cert, nil
}

// GetExpiringCertificates retrieves certificates expiring within the specified days
func (s *Storage) GetExpiringCertificates(days int) ([]*Certificate, error) {
	const query = `
	SELECT id, domain, certificate, private_key, issuer_cert, not_before, not_after, created_at, updated_at
	FROM certificates
	WHERE not_after <= datetime('now', '+' || ? || ' days')
	`

	rows, err := s.db.Query(query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		cert := &Certificate{}
		err := rows.Scan(&cert.ID, &cert.Domain, &cert.Certificate, &cert.PrivateKey, &cert.IssuerCert, &cert.NotBefore, &cert.NotAfter, &cert.CreatedAt, &cert.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, rows.Err()
}

// SaveLECredentials saves or updates Let's Encrypt credentials
func (s *Storage) SaveLECredentials(creds *LECredentials) error {
	const query = `
	INSERT INTO le_credentials (email, key_type, key, updated_at)
	VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(email) DO UPDATE SET
		key_type = excluded.key_type,
		key = excluded.key,
		updated_at = CURRENT_TIMESTAMP
	`

	result, err := s.db.Exec(query, creds.Email, creds.KeyType, creds.Key)
	if err != nil {
		return fmt.Errorf("failed to save LE credentials: %w", err)
	}

	if creds.ID == 0 {
		id, err := result.LastInsertId()
		if err == nil {
			creds.ID = id
		}
	}

	return nil
}

// GetLECredentials retrieves Let's Encrypt credentials by email
func (s *Storage) GetLECredentials(email string) (*LECredentials, error) {
	const query = `
	SELECT id, email, key_type, key, created_at, updated_at
	FROM le_credentials
	WHERE email = ?
	`

	creds := &LECredentials{}
	err := s.db.
		QueryRow(query, email).
		Scan(&creds.ID, &creds.Email, &creds.KeyType, &creds.Key, &creds.CreatedAt, &creds.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get LE credentials: %w", err)
	}

	return creds, nil
}
