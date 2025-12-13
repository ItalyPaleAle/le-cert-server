package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"iter"

	"tailscale.com/ipn"
)

type TSNetStorage struct {
	db *sql.DB
}

func (s *Storage) TSNetStorage() *TSNetStorage {
	return &TSNetStorage{
		db: s.db,
	}
}

// ReadState implements the ipn.StateStore interface.
func (t *TSNetStorage) ReadState(id ipn.StateKey) ([]byte, error) {
	queryCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	var data []byte
	err := t.db.QueryRowContext(queryCtx,
		`SELECT data FROM tsnet_state WHERE id = ?`,
		string(id),
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ipn.ErrStateNotExist
	} else if err != nil {
		return nil, fmt.Errorf("failed to get tsnet state: %w", err)
	}
	return data, nil
}

// WriteState implements the ipn.StateStore interface.
func (t *TSNetStorage) WriteState(id ipn.StateKey, bs []byte) error {
	// Check if the value has changed
	existing, err := t.ReadState(id)
	if err == nil && bytes.Equal(existing, bs) {
		return nil
	}

	queryCtx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	_, err = t.db.ExecContext(queryCtx,
		`INSERT INTO tsnet_state (id, data) VALUES (?, ?)
		 ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
		string(id), bs,
	)
	return fmt.Errorf("failed to save tsnet state: %w", err)
}

// All implements the ipn.ExportableStore interface and returns an iterator over all store keys.
func (t *TSNetStorage) All() iter.Seq2[ipn.StateKey, []byte] {
	return func(yield func(ipn.StateKey, []byte) bool) {
		//nolint:rowserrcheck
		rows, err := t.db.QueryContext(context.Background(),
			`SELECT id, data FROM tsnet_state`,
		)
		if err != nil {
			return
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var (
				id   string
				data []byte
			)
			err = rows.Scan(&id, &data)
			if err != nil {
				return
			}
			if !yield(ipn.StateKey(id), data) {
				return
			}
		}
	}
}
