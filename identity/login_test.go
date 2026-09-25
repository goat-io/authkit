package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// fakeSigner is an in-memory Signer for tests (no crypto): it serializes claims to
// JSON and enforces expiry, which is all LoginService needs from the challenge.
type fakeSigner struct{ now func() time.Time }

func (f fakeSigner) Mint(c Claims, ttl time.Duration) (string, time.Time, error) {
	c.ExpiresAt = f.now().Add(ttl)
	b, _ := json.Marshal(c)
	return string(b), c.ExpiresAt, nil
}
func (f fakeSigner) Verify(tok string) (Claims, error) {
	var c Claims
	if err := json.Unmarshal([]byte(tok), &c); err != nil {
		return Claims{}, err
	}
	if !c.ExpiresAt.IsZero() && f.now().After(c.ExpiresAt) {
		return Claims{}, errors.New("expired")
	}
	return c, nil
}
func (f fakeSigner) JWKS() map[string]any { return map[string]any{} }

func TestLoginMFAGate(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return now }

	users := newMemUserStore()
	pw, _ := HashPassword("hunter2hunter2")
	_ = users.Create(ctx, User{ID: "u1", Email: "a@b.co", PasswordHash: pw})
	sessions := NewSessionService(newMemSessionStore(), users, nil, time.Hour)
	mfa := NewMFAService(newMemMFA())
	signer := fakeSigner{now: clock}
	loginSvc := NewLoginService(sessions, users, mfa, signer)
	loginSvc.now = clock

	// 1. No MFA enrolled → password login returns a session immediately.
	res, err := loginSvc.Login(ctx, "a@b.co", "hunter2hunter2")
	if err != nil || res.MFARequired || res.Session == "" {
		t.Fatalf("plain login should yield a session: %+v err=%v", res, err)
	}
	// wrong password is rejected
	if _, err := loginSvc.Login(ctx, "a@b.co", "nope"); err != ErrInvalidLogin {
		t.Fatalf("want ErrInvalidLogin, got %v", err)
	}

	// 2. Enrol + activate TOTP.
	secret, _, _ := mfa.BeginEnrolment(ctx, "u1", "Delphi", "a@b.co")
	if err := mfa.ConfirmEnrolment(ctx, "u1", liveTOTP(t, secret, now), now); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// 3. Now password login must NOT yield a session — only a challenge.
	res, err = loginSvc.Login(ctx, "a@b.co", "hunter2hunter2")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !res.MFARequired || res.Challenge == "" || res.Session != "" {
		t.Fatalf("MFA account must be gated, got %+v", res)
	}
	if NewAuthenticator("", signer).Authenticate(ctx, res.Challenge).Authenticated() {
		t.Fatal("MFA challenge must not authenticate as a machine token")
	}

	// 4. Wrong code is rejected; correct code yields a session.
	if _, err := loginSvc.CompleteMFA(ctx, res.Challenge, "000000"); err != ErrMFAInvalidCode {
		t.Fatalf("bad code: want ErrMFAInvalidCode, got %v", err)
	}
	token, err := loginSvc.CompleteMFA(ctx, res.Challenge, liveTOTP(t, secret, now))
	if err != nil || token == "" {
		t.Fatalf("CompleteMFA should yield a session: tok=%q err=%v", token, err)
	}

	// 5. A forged challenge (no mfa_pending scope) is rejected.
	bogus, _, _ := signer.Mint(Claims{Subject: "u1"}, time.Minute)
	if _, err := loginSvc.CompleteMFA(ctx, bogus, liveTOTP(t, secret, now)); err != ErrMFAInvalidCode {
		t.Fatalf("challenge without scope must be rejected, got %v", err)
	}
}
