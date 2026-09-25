package identity

import (
	"context"
	"time"
)

// ports.go — the driven interfaces. Adapters (token/eddsa, store/postgres, …)
// implement these; the core never imports a JWT library, a database driver, or a
// web framework.

// Signer mints and verifies short-lived access tokens, and publishes its public
// verification key. The default adapter is token/eddsa (EdDSA + JWKS).
type Signer interface {
	Mint(claims Claims, ttl time.Duration) (token string, expiresAt time.Time, err error)
	Verify(token string) (Claims, error)
	JWKS() map[string]any
}

// Credential is a durable, revocable machine credential (a runner's "client
// secret"). Only its hash is stored; it binds to a subject on first exchange.
type Credential struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"orgId"`
	Subject    string     `json:"subject"`           // bound runner id (empty until first exchange)
	Name       string     `json:"name"`
	SecretHash string     `json:"-"`                 // never serialized
	Scopes     []string   `json:"scopes,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

func (c Credential) Revoked() bool { return c.RevokedAt != nil }

// CredentialStore persists machine credentials. The Postgres adapter is in
// store/postgres; apps with an existing store can wrap it to satisfy this port.
type CredentialStore interface {
	Create(ctx context.Context, c Credential) error
	GetByHash(ctx context.Context, secretHash string) (Credential, error)
	Bind(ctx context.Context, id, subject string) error
	Touch(ctx context.Context, id string) error
	Revoke(ctx context.Context, id string) error
	List(ctx context.Context, orgID string) ([]Credential, error)
}

// --- user/session ports (defined now so the shape is stable; implement when a
// service needs human login — WebAuthn/sessions, mirroring walliver). ---

// Session is an opaque, server-side user session (stored as a hash). StepUp marks
// a short-TTL ELEVATED session minted after a second-factor proof (see stepup.go);
// a normal login session is never StepUp, so a step-up gate is real.
type Session struct {
	TokenHash string
	UserID    string
	ExpiresAt time.Time
	StepUp    bool
}

// SessionStore persists opaque user sessions.
type SessionStore interface {
	Create(ctx context.Context, s Session) error
	Lookup(ctx context.Context, tokenHash string) (Session, bool, error)
	Delete(ctx context.Context, tokenHash string) error
}

// MembershipStore resolves a user's organizations + roles.
type MembershipStore interface {
	MembershipsOf(ctx context.Context, userID string) ([]Membership, error)
}
