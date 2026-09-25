package identity

import (
	"context"
	"errors"
)

// SocialIdentity is a verified OpenID Connect subject. Provider + Subject is
// the stable account key; email is profile data and is never used to link users.
type SocialIdentity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	DisplayName   string
}

var (
	ErrSocialIdentity = errors.New("invalid social identity")
	ErrEmailInUse     = errors.New("email already belongs to another user; sign in and link the social account")
)

// SocialAccountStore atomically resolves or creates users for verified provider
// subjects. Link must reject a subject already attached to a different user.
type SocialAccountStore interface {
	ResolveOrCreate(ctx context.Context, person SocialIdentity) (userID string, err error)
	Link(ctx context.Context, userID string, person SocialIdentity) error
}

// SocialLoginService connects verified provider identities to authkit sessions.
// Link is an explicit action for an already authenticated user.
type SocialLoginService struct {
	accounts SocialAccountStore
	sessions *SessionService
}

func NewSocialLoginService(accounts SocialAccountStore, sessions *SessionService) *SocialLoginService {
	return &SocialLoginService{accounts: accounts, sessions: sessions}
}

func (s *SocialLoginService) SignIn(ctx context.Context, person SocialIdentity) (string, error) {
	userID, err := s.Resolve(ctx, person)
	if err != nil {
		return "", err
	}
	return s.sessions.Issue(ctx, userID)
}

// Resolve returns the local user for a verified provider identity without
// issuing a session, so callers can apply an MFA policy first.
func (s *SocialLoginService) Resolve(ctx context.Context, person SocialIdentity) (string, error) {
	if person.Provider == "" || person.Subject == "" {
		return "", ErrSocialIdentity
	}
	userID, err := s.accounts.ResolveOrCreate(ctx, person)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (s *SocialLoginService) Link(ctx context.Context, current Principal, person SocialIdentity) error {
	if current.Kind != KindUser || current.Subject == "" || person.Provider == "" || person.Subject == "" {
		return ErrSocialIdentity
	}
	return s.accounts.Link(ctx, current.Subject, person)
}
