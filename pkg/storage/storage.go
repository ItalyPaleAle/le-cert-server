package storage

import (
	"context"
	"crypto/tls"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
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
	// Parse and configure the SQLite connection string with WAL mode and busy timeout
	connStr, err := parseSqliteConnectionString(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQLite connection string: %w", err)
	}

	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &Storage{
		db: db,
	}

	return storage, nil
}

// parseSqliteConnectionString parses and configures the SQLite connection string.
// It ensures the connection string starts with "file:", properly handles existing
// query parameters, and adds WAL mode and busy timeout pragmas if not already present.
func parseSqliteConnectionString(connString string) (string, error) {
	// Ensure the connection string starts with "file:"
	if !strings.HasPrefix(connString, "file:") {
		connString = "file:" + connString
	}

	// Parse the connection string as a URL
	connStringUrl, err := url.Parse(connString)
	if err != nil {
		return "", fmt.Errorf("failed to parse connection string: %w", err)
	}

	// Get existing query parameters
	qs := connStringUrl.Query()

	// Check if WAL and busy timeout pragmas are already set
	hasWAL := false
	hasBusyTimeout := false

	for _, p := range qs["_pragma"] {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "journal_mode(") {
			hasWAL = true
		}
		if strings.HasPrefix(p, "busy_timeout(") {
			hasBusyTimeout = true
		}
	}

	// Add WAL mode if not already present
	if !hasWAL {
		qs["_pragma"] = append(qs["_pragma"], "journal_mode(WAL)")
	}

	// Add busy timeout (5000ms = 5s) if not already present
	if !hasBusyTimeout {
		qs["_pragma"] = append(qs["_pragma"], "busy_timeout(5000)")
	}

	// Update the connection string with the new query parameters
	connStringUrl.RawQuery = qs.Encode()

	return connStringUrl.String(), nil
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
