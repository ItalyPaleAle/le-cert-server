package storage

import (
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/italypaleale/go-sql-utils/migrations"
	sqlitemigrations "github.com/italypaleale/go-sql-utils/migrations/sqlite"

	_ "modernc.org/sqlite"
)

// Storage uses a JSON-based SQL convention where each table has a single concrete
// Data JSON column, with all other columns generated from it. The SQL column
// constraints act as dynamic checks on the quality of the JSON data.

//go:embed migrations
var migrationScripts embed.FS

// Storage handles certificate and credential persistence
type Storage struct {
	db      *sql.DB
	running atomic.Bool
}

// Certificate represents a stored TLS certificate
//
//nolint:tagliatelle
type Certificate struct {
	ID          int64     `json:"-"`
	Domain      string    `json:"domain"`
	Certificate []byte    `json:"certificate"`
	PrivateKey  []byte    `json:"private_key"`
	IssuerCert  []byte    `json:"issuer_cert,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GetTLSCertificate returns the tls.Certificate from the Certificate resource
func (c Certificate) GetTLSCertificate() (cert tls.Certificate, err error) {
	cert, err = tls.X509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return cert, fmt.Errorf("failed to parse TLS certificate or key: %w", err)
	}
	return cert, nil
}

// LECredentials represents stored Let's Encrypt credentials
//
//nolint:tagliatelle
type LECredentials struct {
	ID        int64     `json:"-"`
	Email     string    `json:"email"`
	KeyType   string    `json:"key_type"`
	Key       []byte    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
	// Configure connection string with WAL mode and busy timeout
	// Use query parameters to set pragmas for modernc.org/sqlite
	connStr := dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &Storage{
		db: db,
	}

	return storage, nil
}

func (s *Storage) Init(ctx context.Context) error {
	// Perform schema migrations
	err := s.performMigrations(ctx)
	if err != nil {
		return fmt.Errorf("failed to perform schema migrations: %w", err)
	}

	return nil
}

func (s *Storage) performMigrations(ctx context.Context) error {
	log := slog.Default()

	m := sqlitemigrations.Migrations{
		Pool:              s.db,
		MetadataTableName: "metadata",
		MetadataKey:       "migrations-version",
	}

	// Get all migration scripts
	entries, err := migrationScripts.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("error while loading migration scripts: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			// Should not happen...
			continue
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)

	migrationFns := make([]migrations.MigrationFn, len(entries))
	for i, e := range names {
		data, err := migrationScripts.ReadFile(filepath.Join("migrations", e))
		if err != nil {
			return fmt.Errorf("error reading migration script '%s': %w", e, err)
		}

		migrationFns[i] = func(ctx context.Context) error {
			log.InfoContext(ctx, "Performing SQLite database migration", slog.String("migration", e))
			_, err := m.GetConn().ExecContext(ctx, string(data))
			if err != nil {
				return fmt.Errorf("failed to perform migration '%s': %w", e, err)
			}
			return nil
		}
	}

	// Execute the migrations
	err = m.Perform(ctx, migrationFns, log)
	if err != nil {
		return fmt.Errorf("migrations failed with error: %w", err)
	}

	return nil
}

func (s *Storage) Run(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	// Wait for the context to be canceled
	<-ctx.Done()

	// Close the connection
	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("failed to close database connection: %w", err)
	}

	return nil
}

// SaveCertificate saves or updates a certificate
func (s *Storage) SaveCertificate(ctx context.Context, cert *Certificate) error {
	const query = `
	INSERT INTO certificates (data)
	VALUES (json(?))
	ON CONFLICT(domain) DO UPDATE SET
		data = excluded.data
	`

	// Set timestamps
	now := time.Now()
	if cert.CreatedAt.IsZero() {
		cert.CreatedAt = now
	}
	cert.UpdatedAt = now

	// Marshal certificate to JSON
	jsonData, err := json.Marshal(cert)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate: %w", err)
	}

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	result, err := s.db.ExecContext(queryCtx, query, jsonData)
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
func (s *Storage) GetCertificate(ctx context.Context, domain string) (*Certificate, error) {
	const query = `
	SELECT id, data
	FROM certificates
	WHERE domain = ?
	`

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var (
		id       int64
		jsonData []byte
	)
	err := s.db.
		QueryRowContext(queryCtx, query, domain).
		Scan(&id, &jsonData)

	if errors.Is(err, sql.ErrNoRows) {
		//nolint:nilnil
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// Unmarshal JSON data
	cert := &Certificate{ID: id}
	err = json.Unmarshal(jsonData, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificate data: %w", err)
	}

	return cert, nil
}

// GetExpiringCertificates retrieves certificates expiring within the specified days
func (s *Storage) GetExpiringCertificates(ctx context.Context, days int) ([]*Certificate, error) {
	const query = `
	SELECT id, data
	FROM certificates
	WHERE not_after <= unixepoch('now', '+' || ? || ' days')
	`

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(queryCtx, query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to query expiring certificates: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var certs []*Certificate
	for rows.Next() {
		var id int64
		var jsonData []byte
		err = rows.Scan(&id, &jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}

		// Unmarshal JSON data
		cert := &Certificate{ID: id}
		err = json.Unmarshal(jsonData, cert)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal certificate data: %w", err)
		}

		certs = append(certs, cert)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("failed to iterate through results: %w", err)
	}

	return certs, nil
}

// SaveLECredentials saves or updates Let's Encrypt credentials
func (s *Storage) SaveLECredentials(ctx context.Context, creds *LECredentials) error {
	const query = `
	INSERT INTO le_credentials (data)
	VALUES (json(?))
	ON CONFLICT(email) DO UPDATE SET
		data = excluded.data
	`

	// Set timestamps
	now := time.Now()
	if creds.CreatedAt.IsZero() {
		creds.CreatedAt = now
	}
	creds.UpdatedAt = now

	// Marshal credentials to JSON
	jsonData, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("failed to marshal LE credentials: %w", err)
	}

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	result, err := s.db.ExecContext(queryCtx, query, jsonData)
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
func (s *Storage) GetLECredentials(ctx context.Context, email string) (*LECredentials, error) {
	const query = `
	SELECT id, data
	FROM le_credentials
	WHERE email = ?
	`

	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var (
		id       int64
		jsonData []byte
	)
	err := s.db.QueryRowContext(queryCtx, query, email).Scan(&id, &jsonData)

	if errors.Is(err, sql.ErrNoRows) {
		//nolint:nilnil
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get LE credentials: %w", err)
	}

	// Unmarshal JSON data
	creds := &LECredentials{ID: id}
	err = json.Unmarshal(jsonData, creds)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal LE credentials data: %w", err)
	}

	return creds, nil
}
