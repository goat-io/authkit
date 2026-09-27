package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EmailOTPs struct{ pool *pgxpool.Pool }

func NewEmailOTPs(pool *pgxpool.Pool) *EmailOTPs { return &EmailOTPs{pool: pool} }

var _ identity.EmailOTPStore = (*EmailOTPs)(nil)

func (s *EmailOTPs) Save(ctx context.Context, email string, hash []byte, lifetime, cooldown time.Duration) error {
	var saved bool
	err := s.pool.QueryRow(ctx, `INSERT INTO authkit_email_otps (email,code_hash,sent_at,expires_at,attempts)
		VALUES ($1,$2,now(),now()+($3 * interval '1 second'),0)
		ON CONFLICT (email) DO UPDATE SET code_hash=excluded.code_hash,sent_at=excluded.sent_at,
			expires_at=excluded.expires_at,attempts=0
		WHERE authkit_email_otps.sent_at < now()-($4 * interval '1 second')
		RETURNING true`, email, hash, int(lifetime.Seconds()), int(cooldown.Seconds())).Scan(&saved)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ErrEmailOTPCooldown
	}
	return err
}

func (s *EmailOTPs) Consume(ctx context.Context, email string, hash []byte) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var saved []byte
	var expires time.Time
	var attempts int
	err = tx.QueryRow(ctx, `SELECT code_hash,expires_at,attempts FROM authkit_email_otps WHERE email=$1 FOR UPDATE`, email).Scan(&saved, &expires, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if attempts >= 5 || !time.Now().Before(expires) {
		if _, err = tx.Exec(ctx, `DELETE FROM authkit_email_otps WHERE email=$1`, email); err != nil {
			return false, err
		}
		return false, tx.Commit(ctx)
	}
	if subtle.ConstantTimeCompare(saved, hash) != 1 {
		if _, err = tx.Exec(ctx, `UPDATE authkit_email_otps SET attempts=attempts+1 WHERE email=$1`, email); err != nil {
			return false, err
		}
		return false, tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM authkit_email_otps WHERE email=$1`, email); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *EmailOTPs) DeleteIfHash(ctx context.Context, email string, hash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authkit_email_otps WHERE email=$1 AND code_hash=$2`, email, hash)
	return err
}
