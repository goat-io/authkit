package postgres

import (
	"context"
	"errors"

	"github.com/goat-io/authkit/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SSOConnections struct{ pool *pgxpool.Pool }

func NewSSOConnections(pool *pgxpool.Pool) *SSOConnections { return &SSOConnections{pool: pool} }

var _ identity.SSOConnectionStore = (*SSOConnections)(nil)

func (s *SSOConnections) SaveSSO(ctx context.Context, c identity.SSOConnection) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO authkit_sso_connections(org_id,domain,issuer_url,client_id,client_secret,verification_token,verified_at)
	 VALUES($1,$2,$3,$4,$5,$6,NULL) ON CONFLICT(org_id) DO UPDATE SET domain=excluded.domain,issuer_url=excluded.issuer_url,
	 client_id=excluded.client_id,client_secret=excluded.client_secret,verification_token=excluded.verification_token,verified_at=NULL`,
		c.OrgID, c.Domain, c.IssuerURL, c.ClientID, c.ClientSecret, c.VerificationToken)
	return err
}

func scanSSO(row pgx.Row) (identity.SSOConnection, bool, error) {
	var c identity.SSOConnection
	err := row.Scan(&c.OrgID, &c.Domain, &c.IssuerURL, &c.ClientID, &c.ClientSecret, &c.VerificationToken, &c.VerifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.SSOConnection{}, false, nil
	}
	return c, err == nil, err
}

func (s *SSOConnections) GetSSOByOrg(ctx context.Context, orgID string) (identity.SSOConnection, bool, error) {
	return scanSSO(s.pool.QueryRow(ctx, `SELECT org_id,domain,issuer_url,client_id,client_secret,verification_token,verified_at FROM authkit_sso_connections WHERE org_id=$1`, orgID))
}

func (s *SSOConnections) GetSSOByDomain(ctx context.Context, domain string) (identity.SSOConnection, bool, error) {
	return scanSSO(s.pool.QueryRow(ctx, `SELECT org_id,domain,issuer_url,client_id,client_secret,verification_token,verified_at FROM authkit_sso_connections WHERE domain=$1 AND verified_at IS NOT NULL`, domain))
}

func (s *SSOConnections) ListVerifiedSSO(ctx context.Context) ([]identity.SSOConnection, error) {
	rows, err := s.pool.Query(ctx, `SELECT org_id,domain,issuer_url,client_id,client_secret,verification_token,verified_at FROM authkit_sso_connections WHERE verified_at IS NOT NULL ORDER BY org_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.SSOConnection
	for rows.Next() {
		var c identity.SSOConnection
		if err := rows.Scan(&c.OrgID, &c.Domain, &c.IssuerURL, &c.ClientID, &c.ClientSecret, &c.VerificationToken, &c.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SSOConnections) VerifySSO(ctx context.Context, orgID, token string) error {
	result, err := s.pool.Exec(ctx, `UPDATE authkit_sso_connections SET verified_at=now() WHERE org_id=$1 AND verification_token=$2`, orgID, token)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return errors.New("authkit: SSO connection changed during verification")
	}
	return nil
}

func (s *SSOConnections) DeleteSSO(ctx context.Context, orgID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authkit_sso_connections WHERE org_id=$1`, orgID)
	return err
}
