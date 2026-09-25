package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SocialAccounts maps provider subjects to local users. Email matches never
// attach a provider to an existing user; linking requires an explicit call.
type SocialAccounts struct{ pool *pgxpool.Pool }

func NewSocialAccounts(pool *pgxpool.Pool) *SocialAccounts { return &SocialAccounts{pool: pool} }

var _ identity.SocialAccountStore = (*SocialAccounts)(nil)

func (s *SocialAccounts) ResolveOrCreate(ctx context.Context, person identity.SocialIdentity) (string, error) {
	if person.Provider == "" || person.Subject == "" {
		return "", identity.ErrSocialIdentity
	}
	var userID string
	err := s.pool.QueryRow(ctx, `SELECT user_id FROM authkit_social_accounts WHERE provider=$1 AND subject=$2`, person.Provider, person.Subject).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	userID = "usr_" + base64.RawURLEncoding.EncodeToString(b)
	email := ""
	if person.EmailVerified {
		email = person.Email
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO authkit_users(id,email,display_name,password_hash,created_at) VALUES ($1,NULLIF($2,''),$3,'',$4)`, userID, email, person.DisplayName, time.Now().UTC())
	if err != nil {
		if uniqueConstraint(err, "authkit_users_email_key") {
			_ = tx.Rollback(ctx)
			// A concurrent sign-in for the same provider may have won the race.
			if lookupErr := s.pool.QueryRow(ctx, `SELECT user_id FROM authkit_social_accounts WHERE provider=$1 AND subject=$2`, person.Provider, person.Subject).Scan(&userID); lookupErr == nil {
				return userID, nil
			} else if !errors.Is(lookupErr, pgx.ErrNoRows) {
				return "", lookupErr
			}
			return "", identity.ErrEmailInUse
		}
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO authkit_social_accounts(provider,subject,user_id) VALUES ($1,$2,$3)`, person.Provider, person.Subject, userID)
	if err != nil {
		if uniqueConstraint(err, "authkit_social_accounts_pkey") {
			_ = tx.Rollback(ctx)
			// Another request created this account concurrently. Use that user.
			err = s.pool.QueryRow(ctx, `SELECT user_id FROM authkit_social_accounts WHERE provider=$1 AND subject=$2`, person.Provider, person.Subject).Scan(&userID)
			return userID, err
		}
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return userID, nil
}

func (s *SocialAccounts) Link(ctx context.Context, userID string, person identity.SocialIdentity) error {
	if userID == "" || person.Provider == "" || person.Subject == "" {
		return identity.ErrSocialIdentity
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO authkit_social_accounts(provider,subject,user_id) VALUES ($1,$2,$3) ON CONFLICT (provider,subject) DO NOTHING`, person.Provider, person.Subject, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 0 {
		return nil
	}
	var existing string
	if err := s.pool.QueryRow(ctx, `SELECT user_id FROM authkit_social_accounts WHERE provider=$1 AND subject=$2`, person.Provider, person.Subject).Scan(&existing); err != nil {
		return err
	}
	if existing != userID {
		return identity.ErrSocialIdentity
	}
	return nil
}

func uniqueConstraint(err error, name string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == name
}
