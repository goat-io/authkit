package identity

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
	"time"
)

// mfa.go — TOTP enrolment + verification with optional single-use recovery codes.
// Server-authoritative: the TOTP secret and the recovery-code hashes live only in
// the store; the client ever submits a 6-digit code or a backup code. Mirrors
// walliver's mfa.go, library-agnostic and storage-agnostic (ports below).

var (
	// ErrMFANotEnrolled → no ACTIVE secret for the subject.
	ErrMFANotEnrolled = errors.New("mfa not enrolled")
	// ErrMFAInvalidCode → the submitted TOTP code did not verify.
	ErrMFAInvalidCode = errors.New("invalid mfa code")
	// ErrRecoveryInvalidCode → the backup code matched no unused stored code.
	ErrRecoveryInvalidCode = errors.New("invalid recovery code")
)

const (
	// recoveryCodeCount is the size of a freshly minted backup-code set.
	recoveryCodeCount = 10
	// recoveryCodeBytes is the entropy per code (80 bits → 16 base32 chars).
	recoveryCodeBytes = 10
)

// MFAEnrolment is a subject's stored TOTP factor. Secret is the base32 shared
// secret (server-side only); Active is false until the user confirms a live code —
// a begun-but-unconfirmed enrolment never gates a sign-in.
type MFAEnrolment struct {
	Secret string
	Active bool
}

// MFAStore persists per-subject TOTP enrolment. Upsert overwrites any prior
// (e.g. unconfirmed) secret so re-enrolling is clean; Activate flips Active true.
type MFAStore interface {
	Get(ctx context.Context, subject string) (MFAEnrolment, bool, error)
	Upsert(ctx context.Context, subject string, e MFAEnrolment) error
	Activate(ctx context.Context, subject string) error
}

// RecoveryStore persists a subject's UNUSED backup codes as hashes. A code is
// removed (consumed) on a successful verify — single-use. The plaintext is shown
// ONLY at generation; only hashes are ever stored.
type RecoveryStore interface {
	// Replace overwrites the subject's entire set of unused code hashes.
	Replace(ctx context.Context, subject string, hashes []string) error
	// Hashes returns the subject's remaining unused code hashes.
	Hashes(ctx context.Context, subject string) ([]string, error)
	// Consume removes one matching hash (single-use). ok=false ⇒ no such unused code.
	Consume(ctx context.Context, subject, hash string) (ok bool, err error)
}

// MFAService owns TOTP enrolment + verification over an MFAStore. The raw secret
// is returned ONLY by BeginEnrolment (so the app can render the QR); it is never
// read back out afterwards. recovery is optional (nil ⇒ recovery codes disabled).
type MFAService struct {
	store    MFAStore
	recovery RecoveryStore
}

// NewMFAService wires the MFA service. Recovery codes are off until a store is
// attached via WithRecoveryStore.
func NewMFAService(store MFAStore) *MFAService { return &MFAService{store: store} }

// WithRecoveryStore attaches a backup-codes store, enabling GenerateRecoveryCodes /
// VerifyRecoveryCode. Returns the same service for fluent wiring.
func (s *MFAService) WithRecoveryStore(r RecoveryStore) *MFAService {
	s.recovery = r
	return s
}

// BeginEnrolment mints a fresh TOTP secret for subject (stored INACTIVE) and
// returns the secret + an otpauth provisioning URI for the authenticator app.
// Re-calling it rotates the pending secret (the old unconfirmed one is discarded).
func (s *MFAService) BeginEnrolment(ctx context.Context, subject, issuer, account string) (secret, uri string, err error) {
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	if err := s.store.Upsert(ctx, subject, MFAEnrolment{Secret: secret, Active: false}); err != nil {
		return "", "", err
	}
	return secret, TOTPProvisioningURI(secret, issuer, account), nil
}

// ConfirmEnrolment activates MFA for subject iff `code` is a valid TOTP for the
// pending secret at `now`. A wrong code leaves MFA inactive.
func (s *MFAService) ConfirmEnrolment(ctx context.Context, subject, code string, now time.Time) error {
	e, ok, err := s.store.Get(ctx, subject)
	if err != nil {
		return err
	}
	if !ok {
		return ErrMFANotEnrolled
	}
	if !ValidateTOTP(e.Secret, code, now) {
		return ErrMFAInvalidCode
	}
	return s.store.Activate(ctx, subject)
}

// IsEnrolled reports whether subject has ACTIVE MFA (a pending/unconfirmed
// enrolment does not count) — the predicate sign-in uses to decide gating.
func (s *MFAService) IsEnrolled(ctx context.Context, subject string) (bool, error) {
	e, ok, err := s.store.Get(ctx, subject)
	if err != nil {
		return false, err
	}
	return ok && e.Active, nil
}

// Verify checks `code` against subject's ACTIVE secret (the sign-in challenge
// step). Not enrolled/active → ErrMFANotEnrolled; wrong code → ErrMFAInvalidCode.
func (s *MFAService) Verify(ctx context.Context, subject, code string, now time.Time) error {
	e, ok, err := s.store.Get(ctx, subject)
	if err != nil {
		return err
	}
	if !ok || !e.Active {
		return ErrMFANotEnrolled
	}
	if !ValidateTOTP(e.Secret, code, now) {
		return ErrMFAInvalidCode
	}
	return nil
}

// GenerateRecoveryCodes mints a fresh set of single-use backup codes for subject,
// stores them HASHED (overwriting any prior set), and returns the PLAINTEXT codes
// ONCE — the only time they are ever readable.
func (s *MFAService) GenerateRecoveryCodes(ctx context.Context, subject string) ([]string, error) {
	if s.recovery == nil {
		return nil, ErrMFANotEnrolled
	}
	codes := make([]string, recoveryCodeCount)
	hashes := make([]string, recoveryCodeCount)
	for i := range codes {
		code, err := randRecoveryCode()
		if err != nil {
			return nil, err
		}
		h, err := HashPassword(code)
		if err != nil {
			return nil, err
		}
		codes[i] = code
		hashes[i] = h
	}
	if err := s.recovery.Replace(ctx, subject, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifyRecoveryCode checks code against subject's UNUSED backup codes; a match is
// CONSUMED (single-use) and returns true. No match → false with
// ErrRecoveryInvalidCode. The compare is over bcrypt (constant-time per hash).
func (s *MFAService) VerifyRecoveryCode(ctx context.Context, subject, code string) (bool, error) {
	if s.recovery == nil {
		return false, ErrRecoveryInvalidCode
	}
	code = strings.ToUpper(strings.TrimSpace(code))
	hashes, err := s.recovery.Hashes(ctx, subject)
	if err != nil {
		return false, err
	}
	for _, h := range hashes {
		if CheckPassword(h, code) {
			ok, err := s.recovery.Consume(ctx, subject, h)
			if err != nil {
				return false, err
			}
			if !ok {
				// Raced to consume the same code; treat as already used.
				return false, ErrRecoveryInvalidCode
			}
			return true, nil
		}
	}
	return false, ErrRecoveryInvalidCode
}

// recoveryAlphabet is base32 (uppercase, no padding) — unambiguous to read off a
// screen.
var recoveryAlphabet = base32.StdEncoding.WithPadding(base32.NoPadding)

func randRecoveryCode() (string, error) {
	b := make([]byte, recoveryCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return recoveryAlphabet.EncodeToString(b), nil
}
