package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// SecretPrefix tags an authkit machine credential so callers can tell it apart
// from other tokens (e.g. an admin token).
const SecretPrefix = "ak_"

var (
	ErrInvalidCredential = errors.New("invalid credential")
	ErrRevoked           = errors.New("credential revoked")
	ErrWrongSubject      = errors.New("credential bound to a different subject")
	ErrNoSigner          = errors.New("no signer configured")
)

// GenerateSecret returns a fresh high-entropy credential secret.
func GenerateSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return SecretPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// NewID returns a random identifier for a credential row.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "cred_" + base64.RawURLEncoding.EncodeToString(b)
}

// CredentialService mints, exchanges, and revokes durable machine credentials.
// Exchange is the only store-backed auth step; everything after runs on the
// stateless JWT the exchange returns.
type CredentialService struct {
	store      CredentialStore
	signer     Signer
	defaultTTL time.Duration
}

// NewCredentialService builds the service. ttl ≤ 0 defaults to 10 minutes.
func NewCredentialService(store CredentialStore, signer Signer, ttl time.Duration) *CredentialService {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &CredentialService{store: store, signer: signer, defaultTTL: ttl}
}

// Mint creates a new credential for an organization and returns the plaintext
// secret exactly once (only its hash is stored).
func (s *CredentialService) Mint(ctx context.Context, orgID, name string, scopes []string) (string, Credential, error) {
	secret := GenerateSecret()
	cred := Credential{
		ID:         NewID(),
		OrgID:      orgID,
		Name:       name,
		SecretHash: HashSecret(secret),
		Scopes:     scopes,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.store.Create(ctx, cred); err != nil {
		return "", Credential{}, err
	}
	return secret, cred, nil
}

// Exchange validates a presented secret, binds it to subject on first use, and
// mints a short-lived JWT carrying the credential's org + scopes.
func (s *CredentialService) Exchange(ctx context.Context, secret, subject string, ttl time.Duration) (string, time.Time, error) {
	if s.signer == nil {
		return "", time.Time{}, ErrNoSigner
	}
	cred, err := s.store.GetByHash(ctx, HashSecret(secret))
	if err != nil {
		return "", time.Time{}, ErrInvalidCredential
	}
	if cred.Revoked() {
		return "", time.Time{}, ErrRevoked
	}
	if cred.Subject == "" {
		if err := s.store.Bind(ctx, cred.ID, subject); err != nil {
			return "", time.Time{}, err
		}
		cred.Subject = subject
	} else if cred.Subject != subject {
		return "", time.Time{}, ErrWrongSubject
	}
	_ = s.store.Touch(ctx, cred.ID)
	if ttl <= 0 {
		ttl = s.defaultTTL
	}
	return s.signer.Mint(Claims{Subject: cred.Subject, OrgID: cred.OrgID, Scopes: cred.Scopes}, ttl)
}

// Revoke disables a credential by id.
func (s *CredentialService) Revoke(ctx context.Context, id string) error { return s.store.Revoke(ctx, id) }

// List returns an organization's credentials (hashes omitted by the json tag).
func (s *CredentialService) List(ctx context.Context, orgID string) ([]Credential, error) {
	return s.store.List(ctx, orgID)
}
