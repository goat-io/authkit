package identity

import (
	"context"
	"errors"
	"time"
)

// login.go — the password sign-in flow with an optional second factor. It ties the
// SessionService (issues sessions) and the MFAService (TOTP) together so a user
// with active MFA can't get a session from a password alone: the password step
// returns a short-lived, signed CHALLENGE instead, which is exchanged for a
// session only after a valid TOTP / recovery code. The challenge is a stateless
// JWT (Subject = user, scope = mfa_pending) so it works across pods.

// ErrMFARequired indicates the password was correct but a second factor is needed.
var ErrMFARequired = errors.New("mfa required")

const (
	MFAChallengeScope = "mfa_pending"
	mfaChallengeTTL   = 5 * time.Minute
)

// LoginResult is the outcome of a password attempt. Exactly one of Session (login
// complete) or Challenge (MFA still required) is set.
type LoginResult struct {
	Session     string // a usable session token — login is done
	MFARequired bool   // true ⇒ submit a code to CompleteMFA with Challenge
	Challenge   string // short-lived token proving the password step passed
}

// LoginService orchestrates password + MFA sign-in. mfa/signer may be nil, in
// which case it behaves like a plain password login (no second factor).
type LoginService struct {
	sessions *SessionService
	users    UserStore
	mfa      *MFAService
	signer   Signer
	now      func() time.Time
}

// NewLoginService wires the flow. With a nil mfa or signer, MFA gating is off.
func NewLoginService(sessions *SessionService, users UserStore, mfa *MFAService, signer Signer) *LoginService {
	return &LoginService{sessions: sessions, users: users, mfa: mfa, signer: signer, now: time.Now}
}

// Login verifies the password. If the user has active MFA, it returns a challenge
// (MFARequired) instead of a session; otherwise it issues a session immediately.
func (s *LoginService) Login(ctx context.Context, email, password string) (LoginResult, error) {
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil || !CheckPassword(u.PasswordHash, password) {
		return LoginResult{}, ErrInvalidLogin
	}
	if s.mfa != nil && s.signer != nil {
		if enrolled, _ := s.mfa.IsEnrolled(ctx, u.ID); enrolled {
			challenge, _, merr := s.signer.Mint(Claims{Subject: u.ID, Scopes: []string{MFAChallengeScope}}, mfaChallengeTTL)
			if merr != nil {
				return LoginResult{}, merr
			}
			return LoginResult{MFARequired: true, Challenge: challenge}, nil
		}
	}
	token, err := s.sessions.Issue(ctx, u.ID)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Session: token}, nil
}

// CompleteMFA exchanges a challenge + a TOTP (or single-use recovery) code for a
// session. An invalid/expired challenge or wrong code yields ErrMFAInvalidCode.
func (s *LoginService) CompleteMFA(ctx context.Context, challenge, code string) (string, error) {
	if s.signer == nil || s.mfa == nil {
		return "", ErrInvalidLogin
	}
	claims, err := s.signer.Verify(challenge)
	if err != nil || claims.Subject == "" || !scopeContains(claims.Scopes, MFAChallengeScope) {
		return "", ErrMFAInvalidCode
	}
	userID := claims.Subject
	if verr := s.mfa.Verify(ctx, userID, code, s.now()); verr != nil {
		// fall back to a recovery code
		if ok, rerr := s.mfa.VerifyRecoveryCode(ctx, userID, code); rerr != nil || !ok {
			return "", ErrMFAInvalidCode
		}
	}
	return s.sessions.Issue(ctx, userID)
}

func scopeContains(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
