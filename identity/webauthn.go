package identity

import (
	"context"
	"time"
)

// webauthn.go — the passkey (WebAuthn) port. The ceremony logic lives in the
// webauthn/gowebauthn adapter (over go-webauthn); the stored passkey + its store
// are defined here so the core stays library-agnostic.

// WebAuthnCredential is a stored passkey bound to a user.
type WebAuthnCredential struct {
	ID              []byte    `json:"id"` // raw credential id
	UserID          string    `json:"userId"`
	PublicKey       []byte    `json:"-"`
	AttestationType string    `json:"attestationType,omitempty"`
	AAGUID          []byte    `json:"aaguid,omitempty"`
	SignCount       uint32    `json:"signCount"`
	Transports      []string  `json:"transports,omitempty"`
	// BackupEligible (BE) / BackupState (BS) are the credential's backup flags.
	// They MUST be persisted at registration and restored at login: go-webauthn
	// rejects an assertion whose BE flag differs from the stored one (synced
	// passkeys — iCloud Keychain, Google Password Manager — set BE=true).
	BackupEligible bool      `json:"backupEligible,omitempty"`
	BackupState    bool      `json:"backupState,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

// WebAuthnCredentialStore persists passkeys. The Postgres adapter is in
// store/postgres.
type WebAuthnCredentialStore interface {
	Add(ctx context.Context, c WebAuthnCredential) error
	ListByUser(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	// Delete removes one of the user's passkeys (scoped by userID so a caller can
	// only delete their own). No-op if it doesn't exist / isn't theirs.
	Delete(ctx context.Context, userID string, credentialID []byte) error
}
