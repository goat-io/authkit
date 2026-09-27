package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrEmailOTPUnavailable = errors.New("email OTP is not configured")
	ErrEmailOTPCooldown    = errors.New("wait before requesting another email code")
	ErrEmailOTPInvalid     = errors.New("invalid or expired email code")
)

// EmailOTPStore persists short-lived, hashed codes. Implementations must
// enforce the cooldown and atomically consume a successful code.
type EmailOTPStore interface {
	Save(ctx context.Context, email string, codeHash []byte, lifetime, cooldown time.Duration) error
	Consume(ctx context.Context, email string, codeHash []byte) (bool, error)
	DeleteIfHash(ctx context.Context, email string, codeHash []byte) error
}

// EmailOTPSender sends a code through the application's chosen mail transport.
type EmailOTPSender func(context.Context, string, string) error

// EmailOTPService is a reusable email sign-in factor. It sends a six-digit code,
// verifies it once, creates an unassigned user on first successful proof, and
// issues the normal AuthKit human session. Applications enforce their own
// account/SSO policy before calling Start and Finish.
type EmailOTPService struct {
	store    EmailOTPStore
	users    UserStore
	sessions *SessionService
	secret   []byte
	send     EmailOTPSender
}

func NewEmailOTPService(store EmailOTPStore, users UserStore, sessions *SessionService, secret []byte, send EmailOTPSender) *EmailOTPService {
	return &EmailOTPService{store: store, users: users, sessions: sessions, secret: secret, send: send}
}

func NormalizeEmailOTPAddress(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	address, err := mail.ParseAddress(email)
	if err != nil || len(email) > 320 || address.Address != email {
		return "", errors.New("invalid email")
	}
	return email, nil
}

func (s *EmailOTPService) hash(email, code string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(email))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

func (s *EmailOTPService) Start(ctx context.Context, rawEmail string) (time.Duration, error) {
	if s == nil || s.store == nil || s.send == nil || len(s.secret) == 0 {
		return 0, ErrEmailOTPUnavailable
	}
	email, err := NormalizeEmailOTPAddress(rawEmail)
	if err != nil {
		return 0, err
	}
	var random [4]byte
	if _, err = rand.Read(random[:]); err != nil {
		return 0, err
	}
	n := uint32(random[0])<<24 | uint32(random[1])<<16 | uint32(random[2])<<8 | uint32(random[3])
	code := fmt.Sprintf("%06d", n%1000000)
	hash := s.hash(email, code)
	const cooldown = 30 * time.Second
	if err = s.store.Save(ctx, email, hash, 10*time.Minute, cooldown); err != nil {
		return 0, err
	}
	if err = s.send(ctx, email, code); err != nil {
		_ = s.store.DeleteIfHash(ctx, email, hash)
		return 0, err
	}
	return cooldown, nil
}

func (s *EmailOTPService) Finish(ctx context.Context, rawEmail, code string) (string, error) {
	if s == nil || s.store == nil || s.users == nil || s.sessions == nil || len(s.secret) == 0 {
		return "", ErrEmailOTPUnavailable
	}
	email, err := NormalizeEmailOTPAddress(rawEmail)
	if err != nil {
		return "", err
	}
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return "", ErrEmailOTPInvalid
	}
	valid, err := s.store.Consume(ctx, email, s.hash(email, code))
	if err != nil {
		return "", err
	}
	if !valid {
		return "", ErrEmailOTPInvalid
	}
	user, err := s.users.GetByEmail(ctx, email)
	if errors.Is(err, ErrUserNotFound) {
		user = User{ID: "user_" + uuid.NewString(), Email: email, CreatedAt: time.Now().UTC()}
		if createErr := s.users.Create(ctx, user); createErr != nil {
			// A concurrent social or email sign-in may have created the user.
			user, err = s.users.GetByEmail(ctx, email)
			if err != nil {
				return "", createErr
			}
		}
	} else if err != nil {
		return "", err
	}
	return s.sessions.Issue(ctx, user.ID)
}
