package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Flows stores callback state and WebAuthn ceremonies for one-time consumption.
type Flows struct{ pool *pgxpool.Pool }

func NewFlows(pool *pgxpool.Pool) *Flows { return &Flows{pool: pool} }

func (s *Flows) Put(ctx context.Context, id, kind string, payload []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO authkit_flows(id,kind,payload,expires_at) VALUES ($1,$2,$3,$4)`, id, kind, payload, expiresAt)
	return err
}

func (s *Flows) Take(ctx context.Context, id, kind string) ([]byte, bool, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `DELETE FROM authkit_flows WHERE id=$1 AND kind=$2 AND expires_at>now() RETURNING payload`, id, kind).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return payload, true, nil
}

// PurgeExpired removes abandoned flows; call periodically in long-running apps.
func (s *Flows) PurgeExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authkit_flows WHERE expires_at < now()`)
	return err
}
