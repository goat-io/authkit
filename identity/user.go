package identity

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// user.go — the human side of authkit. A User is a person; they authenticate with
// a factor (password here; WebAuthn/MFA are additional factors layered on top) and
// receive an opaque server-side session. Passwords are bcrypt-hashed.

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	DisplayName  string    `json:"displayName,omitempty"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

// UserStore persists users. The Postgres adapter is in store/postgres.
type UserStore interface {
	Create(ctx context.Context, u User) error
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
}

// HashPassword bcrypts a plaintext password for storage.
func HashPassword(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword verifies a plaintext password against a bcrypt hash (constant time).
func CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}
