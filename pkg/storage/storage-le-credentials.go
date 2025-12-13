package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

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

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
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

	queryCtx, cancel := context.WithTimeout(ctx, queryTimeout)
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
