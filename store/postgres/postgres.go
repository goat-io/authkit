// Package postgres is authkit's canonical storage adapter: pgx-backed
// implementations of the identity ports (credentials, users, memberships,
// sessions) plus the schema. This is the "one way to store auth in our own DB".
//
// Each port has a Create method, so each is its own small type over a shared pool.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema is authkit's DDL. Apply with Migrate; idempotent.
const Schema = `
CREATE TABLE IF NOT EXISTS authkit_orgs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS authkit_sso_connections (
  org_id TEXT PRIMARY KEY REFERENCES authkit_orgs(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  issuer_url TEXT NOT NULL,
  client_id TEXT NOT NULL,
  client_secret TEXT NOT NULL,
  verification_token TEXT NOT NULL,
  verified_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS authkit_sso_verified_domain ON authkit_sso_connections(domain) WHERE verified_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS authkit_users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE authkit_users ALTER COLUMN email DROP NOT NULL;
CREATE TABLE IF NOT EXISTS authkit_social_accounts (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES authkit_users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, subject)
);
CREATE INDEX IF NOT EXISTS idx_authkit_social_accounts_user ON authkit_social_accounts(user_id);
CREATE TABLE IF NOT EXISTS authkit_flows (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  payload BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authkit_flows_expiry ON authkit_flows(expires_at);
CREATE TABLE IF NOT EXISTS authkit_memberships (
  user_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  PRIMARY KEY (user_id, org_id)
);
CREATE TABLE IF NOT EXISTS authkit_teams (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES authkit_orgs(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, slug),
  UNIQUE (id, org_id)
);
CREATE TABLE IF NOT EXISTS authkit_team_memberships (
  team_id TEXT NOT NULL REFERENCES authkit_teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES authkit_users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_authkit_teams_org ON authkit_teams(org_id);
CREATE INDEX IF NOT EXISTS idx_authkit_team_memberships_user ON authkit_team_memberships(user_id);
CREATE TABLE IF NOT EXISTS authkit_credentials (
  id TEXT PRIMARY KEY,
  secret_hash TEXT UNIQUE NOT NULL,
  org_id TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  scopes TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_authkit_credentials_org ON authkit_credentials(org_id);
CREATE TABLE IF NOT EXISTS authkit_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  step_up BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS authkit_mfa (
  subject TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS authkit_mfa_recovery_codes (
  subject TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  PRIMARY KEY (subject, code_hash)
);
CREATE TABLE IF NOT EXISTS authkit_webauthn_credentials (
  id BYTEA PRIMARY KEY,
  user_id TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  attestation_type TEXT NOT NULL DEFAULT '',
  aaguid BYTEA,
  sign_count BIGINT NOT NULL DEFAULT 0,
  transports TEXT[] NOT NULL DEFAULT '{}',
  backup_eligible BOOLEAN NOT NULL DEFAULT false,
  backup_state BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_authkit_webauthn_user ON authkit_webauthn_credentials(user_id);
-- Added after the table first shipped; idempotent so existing DBs pick them up.
ALTER TABLE authkit_webauthn_credentials ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE authkit_webauthn_credentials ADD COLUMN IF NOT EXISTS backup_state BOOLEAN NOT NULL DEFAULT false;
`

// Migrate applies the authkit schema.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, Schema)
	return err
}

// --- credentials -----------------------------------------------------------

type Credentials struct{ pool *pgxpool.Pool }

func NewCredentials(pool *pgxpool.Pool) *Credentials { return &Credentials{pool} }

var _ identity.CredentialStore = (*Credentials)(nil)

func (s *Credentials) Create(ctx context.Context, c identity.Credential) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO authkit_credentials(id, secret_hash, org_id, subject, name, scopes, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		c.ID, c.SecretHash, c.OrgID, c.Subject, c.Name, c.Scopes, c.CreatedAt)
	return err
}

func (s *Credentials) GetByHash(ctx context.Context, hash string) (identity.Credential, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, secret_hash, org_id, subject, name, scopes, created_at, last_used_at, revoked_at FROM authkit_credentials WHERE secret_hash=$1`, hash)
	var c identity.Credential
	if err := row.Scan(&c.ID, &c.SecretHash, &c.OrgID, &c.Subject, &c.Name, &c.Scopes, &c.CreatedAt, &c.LastUsedAt, &c.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return identity.Credential{}, identity.ErrInvalidCredential
		}
		return identity.Credential{}, err
	}
	return c, nil
}

func (s *Credentials) Bind(ctx context.Context, id, subject string) error {
	_, err := s.pool.Exec(ctx, `UPDATE authkit_credentials SET subject=$1 WHERE id=$2`, subject, id)
	return err
}

func (s *Credentials) Touch(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE authkit_credentials SET last_used_at=now() WHERE id=$1`, id)
	return err
}

func (s *Credentials) Revoke(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE authkit_credentials SET revoked_at=now() WHERE id=$1`, id)
	return err
}

func (s *Credentials) List(ctx context.Context, orgID string) ([]identity.Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, secret_hash, org_id, subject, name, scopes, created_at, last_used_at, revoked_at FROM authkit_credentials WHERE ($1='' OR org_id=$1) ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Credential
	for rows.Next() {
		var c identity.Credential
		if err := rows.Scan(&c.ID, &c.SecretHash, &c.OrgID, &c.Subject, &c.Name, &c.Scopes, &c.CreatedAt, &c.LastUsedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- users -----------------------------------------------------------------

type Users struct{ pool *pgxpool.Pool }

func NewUsers(pool *pgxpool.Pool) *Users { return &Users{pool} }

var _ identity.UserStore = (*Users)(nil)

func (s *Users) Create(ctx context.Context, u identity.User) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO authkit_users(id, email, display_name, password_hash, created_at) VALUES ($1,NULLIF($2,''),$3,$4,$5)`,
		u.ID, u.Email, u.DisplayName, u.PasswordHash, u.CreatedAt)
	return err
}

func (s *Users) scan(row pgx.Row) (identity.User, error) {
	var u identity.User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.PasswordHash, &u.CreatedAt)
	return u, err
}

func (s *Users) GetByEmail(ctx context.Context, email string) (identity.User, error) {
	return s.scan(s.pool.QueryRow(ctx, `SELECT id, COALESCE(email,''), display_name, password_hash, created_at FROM authkit_users WHERE email=$1`, email))
}

func (s *Users) GetByID(ctx context.Context, id string) (identity.User, error) {
	return s.scan(s.pool.QueryRow(ctx, `SELECT id, COALESCE(email,''), display_name, password_hash, created_at FROM authkit_users WHERE id=$1`, id))
}

// --- memberships -----------------------------------------------------------

type Memberships struct{ pool *pgxpool.Pool }

func NewMemberships(pool *pgxpool.Pool) *Memberships { return &Memberships{pool} }

var _ identity.MembershipStore = (*Memberships)(nil)

// Add grants a user a role in an org (upsert).
func (s *Memberships) Add(ctx context.Context, userID, orgID, role string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO authkit_memberships(user_id, org_id, role) VALUES ($1,$2,$3) ON CONFLICT (user_id, org_id) DO UPDATE SET role=excluded.role`,
		userID, orgID, role)
	return err
}

// EnsureMembership grants SSO access without changing an existing role.
func (s *Memberships) EnsureMembership(ctx context.Context, userID, orgID, role string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO authkit_memberships(user_id, org_id, role) VALUES ($1,$2,$3) ON CONFLICT (user_id, org_id) DO NOTHING`, userID, orgID, role)
	return err
}

func (s *Memberships) MembershipsOf(ctx context.Context, userID string) ([]identity.Membership, error) {
	rows, err := s.pool.Query(ctx, `SELECT org_id, role FROM authkit_memberships WHERE user_id=$1 ORDER BY org_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Membership
	for rows.Next() {
		var m identity.Membership
		if err := rows.Scan(&m.OrgID, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- sessions --------------------------------------------------------------

type Sessions struct{ pool *pgxpool.Pool }

func NewSessions(pool *pgxpool.Pool) *Sessions { return &Sessions{pool} }

var _ identity.SessionStore = (*Sessions)(nil)

func (s *Sessions) Create(ctx context.Context, sess identity.Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO authkit_sessions(token_hash, user_id, expires_at, step_up) VALUES ($1,$2,$3,$4)`, sess.TokenHash, sess.UserID, sess.ExpiresAt, sess.StepUp)
	return err
}

func (s *Sessions) Lookup(ctx context.Context, hash string) (identity.Session, bool, error) {
	var sess identity.Session
	err := s.pool.QueryRow(ctx, `SELECT token_hash, user_id, expires_at, step_up FROM authkit_sessions WHERE token_hash=$1`, hash).
		Scan(&sess.TokenHash, &sess.UserID, &sess.ExpiresAt, &sess.StepUp)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Session{}, false, nil
	}
	if err != nil {
		return identity.Session{}, false, err
	}
	return sess, true, nil
}

func (s *Sessions) Delete(ctx context.Context, hash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authkit_sessions WHERE token_hash=$1`, hash)
	return err
}

// PurgeExpired removes sessions past their expiry (call periodically).
func (s *Sessions) PurgeExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authkit_sessions WHERE expires_at < $1`, time.Now().UTC())
	return err
}

// --- webauthn credentials --------------------------------------------------

type WebAuthnCredentials struct{ pool *pgxpool.Pool }

func NewWebAuthnCredentials(pool *pgxpool.Pool) *WebAuthnCredentials {
	return &WebAuthnCredentials{pool}
}

var _ identity.WebAuthnCredentialStore = (*WebAuthnCredentials)(nil)

func (s *WebAuthnCredentials) Add(ctx context.Context, c identity.WebAuthnCredential) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO authkit_webauthn_credentials(id, user_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())`,
		c.ID, c.UserID, c.PublicKey, c.AttestationType, c.AAGUID, int64(c.SignCount), c.Transports, c.BackupEligible, c.BackupState)
	return err
}

func (s *WebAuthnCredentials) ListByUser(ctx context.Context, userID string) ([]identity.WebAuthnCredential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state, created_at FROM authkit_webauthn_credentials WHERE user_id=$1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.WebAuthnCredential
	for rows.Next() {
		var c identity.WebAuthnCredential
		var signCount int64
		if err := rows.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.AttestationType, &c.AAGUID, &signCount, &c.Transports, &c.BackupEligible, &c.BackupState, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SignCount = uint32(signCount)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *WebAuthnCredentials) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	_, err := s.pool.Exec(ctx, `UPDATE authkit_webauthn_credentials SET sign_count=$1 WHERE id=$2`, int64(signCount), credentialID)
	return err
}

func (s *WebAuthnCredentials) Delete(ctx context.Context, userID string, credentialID []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM authkit_webauthn_credentials WHERE user_id=$1 AND id=$2`, userID, credentialID)
	return err
}

// --- mfa (TOTP enrolment) --------------------------------------------------

type MFA struct{ pool *pgxpool.Pool }

func NewMFA(pool *pgxpool.Pool) *MFA { return &MFA{pool} }

var _ identity.MFAStore = (*MFA)(nil)

func (s *MFA) Get(ctx context.Context, subject string) (identity.MFAEnrolment, bool, error) {
	var e identity.MFAEnrolment
	err := s.pool.QueryRow(ctx, `SELECT secret, active FROM authkit_mfa WHERE subject=$1`, subject).Scan(&e.Secret, &e.Active)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.MFAEnrolment{}, false, nil
	}
	if err != nil {
		return identity.MFAEnrolment{}, false, err
	}
	return e, true, nil
}

func (s *MFA) Upsert(ctx context.Context, subject string, e identity.MFAEnrolment) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO authkit_mfa(subject, secret, active) VALUES ($1,$2,$3)
		 ON CONFLICT (subject) DO UPDATE SET secret=excluded.secret, active=excluded.active`,
		subject, e.Secret, e.Active)
	return err
}

func (s *MFA) Activate(ctx context.Context, subject string) error {
	ct, err := s.pool.Exec(ctx, `UPDATE authkit_mfa SET active=true WHERE subject=$1`, subject)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return identity.ErrMFANotEnrolled
	}
	return nil
}

// --- mfa recovery codes ----------------------------------------------------

type MFARecovery struct{ pool *pgxpool.Pool }

func NewMFARecovery(pool *pgxpool.Pool) *MFARecovery { return &MFARecovery{pool} }

var _ identity.RecoveryStore = (*MFARecovery)(nil)

func (s *MFARecovery) Replace(ctx context.Context, subject string, hashes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM authkit_mfa_recovery_codes WHERE subject=$1`, subject); err != nil {
		return err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(ctx, `INSERT INTO authkit_mfa_recovery_codes(subject, code_hash) VALUES ($1,$2)`, subject, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *MFARecovery) Hashes(ctx context.Context, subject string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT code_hash FROM authkit_mfa_recovery_codes WHERE subject=$1`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *MFARecovery) Consume(ctx context.Context, subject, hash string) (bool, error) {
	ct, err := s.pool.Exec(ctx, `DELETE FROM authkit_mfa_recovery_codes WHERE subject=$1 AND code_hash=$2`, subject, hash)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// --- orgs ------------------------------------------------------------------

type Orgs struct{ pool *pgxpool.Pool }

func NewOrgs(pool *pgxpool.Pool) *Orgs { return &Orgs{pool} }

// CreateForUser creates an organization and its owner membership atomically.
func (s *Orgs) CreateForUser(ctx context.Context, o identity.Org, userID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO authkit_orgs(id,name,created_at) VALUES ($1,$2,$3)`, o.ID, o.Name, o.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO authkit_memberships(user_id,org_id,role) VALUES ($1,$2,'owner')`, userID, o.ID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var _ identity.OrgStore = (*Orgs)(nil)

func (s *Orgs) Create(ctx context.Context, o identity.Org) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO authkit_orgs(id, name, created_at) VALUES ($1,$2,$3)`, o.ID, o.Name, o.CreatedAt)
	return err
}

func (s *Orgs) GetByID(ctx context.Context, id string) (identity.Org, bool, error) {
	var o identity.Org
	err := s.pool.QueryRow(ctx, `SELECT id, name, created_at FROM authkit_orgs WHERE id=$1`, id).Scan(&o.ID, &o.Name, &o.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Org{}, false, nil
	}
	if err != nil {
		return identity.Org{}, false, err
	}
	return o, true, nil
}

func (s *Orgs) List(ctx context.Context) ([]identity.Org, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, created_at FROM authkit_orgs ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.Org
	for rows.Next() {
		var o identity.Org
		if err := rows.Scan(&o.ID, &o.Name, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
