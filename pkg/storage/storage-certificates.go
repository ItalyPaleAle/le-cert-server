package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
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

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
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

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
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
