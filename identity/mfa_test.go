package identity

import (
	"context"
	"encoding/base32"
	"sync"
	"testing"
	"time"
)

// liveTOTP computes the current code for secret at now (mirrors ValidateTOTP's
// math) so tests can complete a real enrolment/verify ceremony.
func liveTOTP(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return hotp(key, uint64(now.Unix()/int64(totpStep.Seconds())))
}

// --- in-memory stores ------------------------------------------------------

type memMFA struct {
	mu sync.Mutex
	m  map[string]MFAEnrolment
}

func newMemMFA() *memMFA { return &memMFA{m: map[string]MFAEnrolment{}} }

func (s *memMFA) Get(_ context.Context, subj string) (MFAEnrolment, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[subj]
	return e, ok, nil
}
func (s *memMFA) Upsert(_ context.Context, subj string, e MFAEnrolment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[subj] = e
	return nil
}
func (s *memMFA) Activate(_ context.Context, subj string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[subj]
	if !ok {
		return ErrMFANotEnrolled
	}
	e.Active = true
	s.m[subj] = e
	return nil
}

type memRecovery struct {
	mu sync.Mutex
	m  map[string][]string
}

func newMemRecovery() *memRecovery { return &memRecovery{m: map[string][]string{}} }

func (s *memRecovery) Replace(_ context.Context, subj string, hashes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[subj] = append([]string(nil), hashes...)
	return nil
}
func (s *memRecovery) Hashes(_ context.Context, subj string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.m[subj]...), nil
}
func (s *memRecovery) Consume(_ context.Context, subj, hash string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.m[subj]
	for i, h := range cur {
		if h == hash {
			s.m[subj] = append(cur[:i], cur[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

type memUserStore struct {
	mu sync.Mutex
	m  map[string]User
}

func newMemUserStore() *memUserStore { return &memUserStore{m: map[string]User{}} }

func (s *memUserStore) Create(_ context.Context, u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[u.ID] = u
	return nil
}
func (s *memUserStore) GetByEmail(_ context.Context, email string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.m {
		if u.Email == email {
			return u, nil
		}
	}
	return User{}, ErrInvalidLogin
}
func (s *memUserStore) GetByID(_ context.Context, id string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.m[id]
	if !ok {
		return User{}, ErrInvalidLogin
	}
	return u, nil
}

type memSessionStore struct {
	mu sync.Mutex
	m  map[string]Session
}

func newMemSessionStore() *memSessionStore { return &memSessionStore{m: map[string]Session{}} }

func (s *memSessionStore) Create(_ context.Context, sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sess.TokenHash] = sess
	return nil
}
func (s *memSessionStore) Lookup(_ context.Context, hash string) (Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[hash]
	return sess, ok, nil
}
func (s *memSessionStore) Delete(_ context.Context, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, hash)
	return nil
}

func TestMFAEnrolAndVerify(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	mfa := NewMFAService(newMemMFA())

	// not enrolled yet
	if ok, _ := mfa.IsEnrolled(ctx, "u1"); ok {
		t.Fatal("should not be enrolled before begin")
	}

	secret, uri, err := mfa.BeginEnrolment(ctx, "u1", "Delphi", "a@b.co")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if secret == "" || uri == "" {
		t.Fatal("empty secret/uri")
	}
	// a pending (unconfirmed) enrolment must not gate sign-in
	if ok, _ := mfa.IsEnrolled(ctx, "u1"); ok {
		t.Fatal("pending enrolment should not count as enrolled")
	}
	// wrong code does not activate
	if err := mfa.ConfirmEnrolment(ctx, "u1", "000000", now); err != ErrMFAInvalidCode {
		t.Fatalf("want ErrMFAInvalidCode, got %v", err)
	}
	// confirm with the live code
	if err := mfa.ConfirmEnrolment(ctx, "u1", liveTOTP(t, secret, now), now); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if ok, _ := mfa.IsEnrolled(ctx, "u1"); !ok {
		t.Fatal("should be enrolled after confirm")
	}
	// verify the challenge step
	if err := mfa.Verify(ctx, "u1", liveTOTP(t, secret, now), now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := mfa.Verify(ctx, "u1", "123456", now); err != ErrMFAInvalidCode {
		t.Fatalf("bad code: want ErrMFAInvalidCode, got %v", err)
	}
	// unknown subject
	if err := mfa.Verify(ctx, "ghost", "123456", now); err != ErrMFANotEnrolled {
		t.Fatalf("want ErrMFANotEnrolled, got %v", err)
	}
}

func TestRecoveryCodesSingleUse(t *testing.T) {
	ctx := context.Background()
	mfa := NewMFAService(newMemMFA()).WithRecoveryStore(newMemRecovery())

	codes, err := mfa.GenerateRecoveryCodes(ctx, "u1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(codes) != recoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), recoveryCodeCount)
	}
	// a real code verifies once...
	ok, err := mfa.VerifyRecoveryCode(ctx, "u1", codes[0])
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}
	// ...and is then consumed
	if ok, err := mfa.VerifyRecoveryCode(ctx, "u1", codes[0]); ok || err != ErrRecoveryInvalidCode {
		t.Fatalf("reuse: ok=%v err=%v", ok, err)
	}
	// a bogus code fails
	if ok, err := mfa.VerifyRecoveryCode(ctx, "u1", "NOTACODE"); ok || err != ErrRecoveryInvalidCode {
		t.Fatalf("bogus: ok=%v err=%v", ok, err)
	}
	// regeneration invalidates the old set
	if _, err := mfa.GenerateRecoveryCodes(ctx, "u1"); err != nil {
		t.Fatalf("regen: %v", err)
	}
	if ok, _ := mfa.VerifyRecoveryCode(ctx, "u1", codes[1]); ok {
		t.Fatal("old code should be invalid after regeneration")
	}
}

func TestStepUpTOTPElevatesSession(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	// user with a session service + confirmed MFA
	users := newMemUserStore()
	_ = users.Create(ctx, User{ID: "u1", Email: "a@b.co"})
	sessions := newMemSessionStore()
	sessSvc := NewSessionService(sessions, users, nil, time.Hour)
	auth := NewAuthenticator("admin", nil).WithSessions(sessSvc)

	mfa := NewMFAService(newMemMFA())
	secret, _, _ := mfa.BeginEnrolment(ctx, "u1", "Delphi", "a@b.co")
	_ = mfa.ConfirmEnrolment(ctx, "u1", liveTOTP(t, secret, now), now)

	su := NewStepUpService(sessSvc, time.Minute,
		NewTOTPMethod(mfa, func() time.Time { return now }),
		BiometricMethod{},
	)

	// methods offered: biometric always, totp because enrolled
	methods, err := su.Methods(ctx, "u1")
	if err != nil {
		t.Fatalf("methods: %v", err)
	}
	if len(methods) != 2 || methods[0] != "biometric" || methods[1] != "totp" {
		t.Fatalf("methods = %v, want [biometric totp]", methods)
	}

	// wrong code is rejected, no token minted
	if _, _, err := su.Elevate(ctx, "u1", "totp", StepUpProof{Code: "000000"}); err != ErrStepUpRejected {
		t.Fatalf("want ErrStepUpRejected, got %v", err)
	}
	// unknown method
	if _, _, err := su.Elevate(ctx, "u1", "smoke-signal", StepUpProof{}); err != ErrStepUpMethodUnknown {
		t.Fatalf("want ErrStepUpMethodUnknown, got %v", err)
	}

	// correct code mints an ELEVATED session
	tok, ttl, err := su.Elevate(ctx, "u1", "totp", StepUpProof{Code: liveTOTP(t, secret, now)})
	if err != nil {
		t.Fatalf("elevate: %v", err)
	}
	if ttl != time.Minute {
		t.Fatalf("ttl = %v, want 1m", ttl)
	}
	p := auth.Authenticate(ctx, tok)
	if p.Kind != KindUser || p.Subject != "u1" || !p.StepUp {
		t.Fatalf("elevated principal wrong: %+v", p)
	}

	// a NORMAL login session is never StepUp (the gate is real)
	normal, _ := sessSvc.Issue(ctx, "u1")
	if auth.Authenticate(ctx, normal).StepUp {
		t.Fatal("normal session must not be step-up")
	}
}
