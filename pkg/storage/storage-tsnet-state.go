package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
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
	var data []byte
	err := t.db.QueryRowContext(context.Background(),
		`SELECT data FROM tsnet_state WHERE id = ?`,
		string(id),
	).Scan(&data)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ipn.ErrStateNotExist
		}
		return nil, err
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

	_, err = t.db.ExecContext(context.Background(),
		`INSERT INTO tsnet_state (id, data) VALUES (?, ?)
		 ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
		string(id), bs,
	)
	return err
}

// All implements the ipn.ExportableStore interface and returns an iterator over all store keys.
func (t *TSNetStorage) All() iter.Seq2[ipn.StateKey, []byte] {
	return func(yield func(ipn.StateKey, []byte) bool) {
		rows, err := t.db.QueryContext(context.Background(),
			`SELECT id, data FROM tsnet_state`,
		)
		if err != nil {
			return
		}
		defer rows.Close()

		for rows.Next() {
			var id string
			var data []byte
			if err := rows.Scan(&id, &data); err != nil {
				return
			}
			if !yield(ipn.StateKey(id), data) {
				return
			}
		}
	}
}
