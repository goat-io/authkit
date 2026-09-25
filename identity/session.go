package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// session.go — opaque, server-side user sessions (the human equivalent of the
// machine JWT). The session token is random and high-entropy; only its hash is
// stored, so a database dump never yields a usable credential. Sessions are
// inherently stateful (a lookup resolves the user) — that's the right trade for
// humans (instant revocation), where machines use stateless JWTs.

const SessionPrefix = "aks_"

var ErrInvalidLogin = errors.New("invalid email or password")

// SessionService issues, resolves, and revokes user sessions.
type SessionService struct {
	sessions    SessionStore
	users       UserStore
	memberships MembershipStore
	ttl         time.Duration
}

// NewSessionService builds the service. ttl ≤ 0 defaults to 30 days. memberships
// may be nil (sessions then resolve a user with no org context).
func NewSessionService(sessions SessionStore, users UserStore, memberships MembershipStore, ttl time.Duration) *SessionService {
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	return &SessionService{sessions: sessions, users: users, memberships: memberships, ttl: ttl}
}

// Login verifies a password factor and issues a session token (returned once).
func (s *SessionService) Login(ctx context.Context, email, password string) (string, error) {
	u, err := s.users.GetByEmail(ctx, email)
	if err != nil || !CheckPassword(u.PasswordHash, password) {
		return "", ErrInvalidLogin
	}
	return s.Issue(ctx, u.ID)
}

// Issue mints a session for an already-authenticated user (use after any factor:
// password, WebAuthn, MFA…). Returns the plaintext token once.
func (s *SessionService) Issue(ctx context.Context, userID string) (string, error) {
	return s.issue(ctx, userID, s.ttl, false)
}

// IssueStepUp mints a short-TTL ELEVATED session for an already-authenticated user
// after a second-factor proof, used to pass a step-up gate. ttl ≤ 0 defaults to
// five minutes. Returns the plaintext token once.
func (s *SessionService) IssueStepUp(ctx context.Context, userID string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return s.issue(ctx, userID, ttl, true)
}

func (s *SessionService) issue(ctx context.Context, userID string, ttl time.Duration, stepUp bool) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := SessionPrefix + base64.RawURLEncoding.EncodeToString(b)
	sess := Session{TokenHash: HashSecret(token), UserID: userID, ExpiresAt: time.Now().UTC().Add(ttl), StepUp: stepUp}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return "", err
	}
	return token, nil
}

// Logout revokes a session token.
func (s *SessionService) Logout(ctx context.Context, token string) error {
	return s.sessions.Delete(ctx, HashSecret(token))
}

// Resolve turns a session token into a user Principal (with org memberships), or
// (_, false) if it is unknown/expired.
func (s *SessionService) Resolve(ctx context.Context, token string) (Principal, bool) {
	sess, ok, err := s.sessions.Lookup(ctx, HashSecret(token))
	if err != nil || !ok || sess.ExpiresAt.Before(time.Now().UTC()) {
		return Principal{}, false
	}
	p := Principal{Kind: KindUser, Subject: sess.UserID, StepUp: sess.StepUp}
	if s.memberships != nil {
		if ms, merr := s.memberships.MembershipsOf(ctx, sess.UserID); merr == nil {
			p.Memberships = ms
			if len(ms) > 0 {
				p.OrgID = ms[0].OrgID // default acting org; the app may switch it
				p.Roles = []string{ms[0].Role}
			}
		}
	}
	return p, true
}
