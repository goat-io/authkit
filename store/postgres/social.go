package postgres

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SocialAccounts maps provider subjects to local users. A provider-verified
// email can claim the existing user with that email; unverified claims cannot.
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
	email := ""
	if person.EmailVerified {
		email = strings.ToLower(strings.TrimSpace(person.Email))
	}
	for attempt := 0; attempt < 3; attempt++ {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return "", err
		}
		userID = ""
		if email != "" {
			// Reject ambiguous legacy addresses rather than choosing an account.
			rows, queryErr := tx.Query(ctx, `SELECT id FROM authkit_users WHERE lower(email)=$1 LIMIT 2`, email)
			if queryErr != nil {
				_ = tx.Rollback(ctx)
				return "", queryErr
			}
			for rows.Next() {
				var candidate string
				if err := rows.Scan(&candidate); err != nil {
					rows.Close()
					_ = tx.Rollback(ctx)
					return "", err
				}
				if userID != "" {
					rows.Close()
					_ = tx.Rollback(ctx)
					return "", identity.ErrEmailInUse
				}
				userID = candidate
			}
			queryErr = rows.Err()
			rows.Close()
			if queryErr != nil {
				_ = tx.Rollback(ctx)
				return "", queryErr
			}
		}
		if userID == "" {
			userID = "usr_" + base64.RawURLEncoding.EncodeToString(b)
			_, err = tx.Exec(ctx, `INSERT INTO authkit_users(id,email,display_name,password_hash,created_at) VALUES ($1,NULLIF($2,''),$3,'',$4)`, userID, email, person.DisplayName, time.Now().UTC())
			if err != nil {
				_ = tx.Rollback(ctx)
				if email != "" && uniqueConstraint(err, "authkit_users_email_key") {
					// Another verified sign-in created the user. Read it afresh.
					continue
				}
				return "", err
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO authkit_social_accounts(provider,subject,user_id) VALUES ($1,$2,$3) ON CONFLICT (provider,subject) DO NOTHING`, person.Provider, person.Subject, userID)
		if err != nil {
			_ = tx.Rollback(ctx)
			return "", err
		}
		if tag.RowsAffected() == 0 {
			_ = tx.Rollback(ctx)
			// The stable provider subject takes precedence over an email claim.
			err = s.pool.QueryRow(ctx, `SELECT user_id FROM authkit_social_accounts WHERE provider=$1 AND subject=$2`, person.Provider, person.Subject).Scan(&userID)
			return userID, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
		return userID, nil
	}
	return "", identity.ErrEmailInUse
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
