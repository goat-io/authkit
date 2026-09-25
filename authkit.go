// Package authkit wires authentication services from one application config.
// Mount Auth.Handler at Config.BasePath for the built-in net/http routes.
package authkit

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/goat-io/authkit/social"
	"github.com/goat-io/authkit/store/postgres"
	"github.com/goat-io/authkit/webauthn/gowebauthn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Storage supplies the persistence ports. Postgres returns a complete Storage;
// applications can supply their own implementations.
type Storage struct {
	Migrate        func(context.Context) error
	Flows          FlowStore
	Users          identity.UserStore
	Sessions       identity.SessionStore
	Memberships    identity.MembershipStore
	SocialAccounts identity.SocialAccountStore
	MFA            identity.MFAStore
	Recovery       identity.RecoveryStore
	Passkeys       identity.WebAuthnCredentialStore
	Organizations  identity.OrgStore
}

// FlowStore keeps short-lived, one-time OAuth and passkey challenges. Take must
// atomically remove the flow so a callback cannot replay it.
type FlowStore interface {
	Put(ctx context.Context, id, kind string, payload []byte, expiresAt time.Time) error
	Take(ctx context.Context, id, kind string) (payload []byte, ok bool, err error)
}

func Postgres(pool *pgxpool.Pool) Storage {
	return Storage{
		Migrate: func(ctx context.Context) error { return postgres.Migrate(ctx, pool) },
		Flows:   postgres.NewFlows(pool),
		Users:   postgres.NewUsers(pool), Sessions: postgres.NewSessions(pool),
		Memberships: postgres.NewMemberships(pool), SocialAccounts: postgres.NewSocialAccounts(pool),
		MFA: postgres.NewMFA(pool), Recovery: postgres.NewMFARecovery(pool),
		Passkeys: postgres.NewWebAuthnCredentials(pool), Organizations: postgres.NewOrgs(pool),
	}
}

type EmailAndPassword struct{ Enabled bool }

// SocialProvider is the app-level configuration for one provider. RedirectURL
// defaults to BaseURL + BasePath + "/callback/" + provider name.
type SocialProvider struct {
	ClientID        string
	NativeClientIDs []string
	ClientSecret    string
	RedirectURL     string
	MicrosoftTenant string
	AppleTeamID     string
	AppleKeyID      string
	ApplePrivateKey *ecdsa.PrivateKey
}

// OIDCProvider binds an organization to its own OpenID Connect issuer.
// OrgID must refer to an existing organization.
type OIDCProvider struct {
	OrgID        string
	Domain       string // verified email domain; enforced for managed connections
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type Config struct {
	BaseURL          string
	BasePath         string
	Storage          Storage
	Signer           identity.Signer // required for the two-factor plugin
	AdminToken       string
	EmailAndPassword EmailAndPassword
	SocialProviders  map[string]SocialProvider
	OrganizationSSO  map[string]OIDCProvider
	Plugins          []Plugin
}

// Auth owns the configured services and the ready-to-mount HTTP handler.
type Auth struct {
	Sessions      *identity.SessionService
	Password      *identity.LoginService
	Social        *identity.SocialLoginService
	TwoFactor     *identity.MFAService
	Passkeys      *gowebauthn.Provider
	Organizations identity.OrgStore
	Authenticator *identity.Authenticator

	orgCreator       organizationCreator
	membershipWriter membershipProvisioner
	basePath         string
	secure           bool
	providers        map[string]socialFlow
	ssoOrganizations map[string]string
	ssoDomains       map[string]string
	config           Config
}

type organizationCreator interface {
	CreateForUser(context.Context, identity.Org, string) error
}

type membershipProvisioner interface {
	EnsureMembership(context.Context, string, string, string) error
}

type socialFlow interface {
	Begin() (string, social.Pending, error)
	Complete(context.Context, social.Pending, string, string) (identity.SocialIdentity, error)
}

// SignInWithIDToken verifies a native Google, Microsoft, or Apple ID token and
// returns either an authkit session or a TOTP challenge for the configured user.
// The app must retain a one-time nonce and pass its expected value here.
func (a *Auth) SignInWithIDToken(ctx context.Context, provider, rawIDToken, expectedNonce string) (identity.LoginResult, error) {
	p := a.providers[provider]
	verifier, ok := p.(interface {
		VerifyIDToken(context.Context, string, string) (identity.SocialIdentity, error)
	})
	if !ok || a.Social == nil {
		return identity.LoginResult{}, errors.New("authkit: provider does not support native ID token sign-in")
	}
	person, err := verifier.VerifyIDToken(ctx, rawIDToken, expectedNonce)
	if err != nil {
		return identity.LoginResult{}, err
	}
	if domain := a.ssoDomains[provider]; domain != "" && !validSSOEmail(person, domain) {
		return identity.LoginResult{}, errors.New("authkit: organization email was not verified by the identity provider")
	}
	userID, err := a.Social.Resolve(ctx, person)
	if err != nil {
		return identity.LoginResult{}, err
	}
	if err := a.ensureSSOMembership(ctx, provider, userID); err != nil {
		return identity.LoginResult{}, err
	}
	return a.signInUser(ctx, userID)
}

func (a *Auth) ensureSSOMembership(ctx context.Context, provider, userID string) error {
	orgID := a.ssoOrganizations[provider]
	if orgID == "" {
		return nil
	}
	return a.membershipWriter.EnsureMembership(ctx, userID, orgID, "member")
}

func (a *Auth) signInUser(ctx context.Context, userID string) (identity.LoginResult, error) {
	if a.TwoFactor != nil {
		enrolled, err := a.TwoFactor.IsEnrolled(ctx, userID)
		if err != nil {
			return identity.LoginResult{}, err
		}
		if enrolled {
			challenge, _, err := a.config.Signer.Mint(identity.Claims{Subject: userID, Scopes: []string{identity.MFAChallengeScope}}, 5*time.Minute)
			if err != nil {
				return identity.LoginResult{}, err
			}
			return identity.LoginResult{MFARequired: true, Challenge: challenge}, nil
		}
	}
	token, err := a.Sessions.Issue(ctx, userID)
	if err != nil {
		return identity.LoginResult{}, err
	}
	return identity.LoginResult{Session: token}, nil
}

func New(ctx context.Context, cfg Config) (*Auth, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base == nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") || base.Path != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("authkit: BaseURL must be an http(s) origin without a path")
	}
	if cfg.Storage.Users == nil || cfg.Storage.Sessions == nil {
		return nil, errors.New("authkit: user and session stores are required")
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	if !strings.HasPrefix(cfg.BasePath, "/") || strings.HasSuffix(cfg.BasePath, "/") || strings.Contains(cfg.BasePath, "//") {
		return nil, errors.New("authkit: BasePath must be an absolute path without a trailing slash")
	}
	if len(cfg.SocialProviders)+len(cfg.OrganizationSSO) > 0 {
		if cfg.Storage.Flows == nil || cfg.Storage.SocialAccounts == nil {
			return nil, errors.New("authkit: social sign-in requires flow and social account stores")
		}
		if _, ok := cfg.SocialProviders[social.Apple]; ok && base.Scheme != "https" {
			return nil, errors.New("authkit: Apple web callbacks require HTTPS BaseURL")
		}
	}
	if len(cfg.OrganizationSSO) > 0 {
		if cfg.Storage.Organizations == nil || cfg.Storage.Memberships == nil {
			return nil, errors.New("authkit: organization SSO requires organization and membership stores")
		}
		if _, ok := cfg.Storage.Memberships.(membershipProvisioner); !ok {
			return nil, errors.New("authkit: membership store must support EnsureMembership")
		}
	}
	a := &Auth{basePath: cfg.BasePath, secure: base.Scheme == "https", config: cfg, providers: make(map[string]socialFlow), ssoOrganizations: make(map[string]string), ssoDomains: make(map[string]string)}
	a.Sessions = identity.NewSessionService(cfg.Storage.Sessions, cfg.Storage.Users, cfg.Storage.Memberships, 0)
	a.Authenticator = identity.NewAuthenticator(cfg.AdminToken, cfg.Signer).WithSessions(a.Sessions)
	if cfg.EmailAndPassword.Enabled {
		a.Password = identity.NewLoginService(a.Sessions, cfg.Storage.Users, nil, nil)
	}
	if len(cfg.SocialProviders)+len(cfg.OrganizationSSO) > 0 {
		a.Social = identity.NewSocialLoginService(cfg.Storage.SocialAccounts, a.Sessions)
		for name, c := range cfg.SocialProviders {
			redirect := c.RedirectURL
			if redirect == "" {
				redirect = cfg.BaseURL + cfg.BasePath + "/callback/" + name
			}
			p, err := social.New(ctx, social.Config{Provider: name, ClientID: c.ClientID, NativeClientIDs: c.NativeClientIDs, ClientSecret: c.ClientSecret,
				RedirectURL: redirect, MicrosoftTenant: c.MicrosoftTenant, AppleTeamID: c.AppleTeamID,
				AppleKeyID: c.AppleKeyID, ApplePrivateKey: c.ApplePrivateKey})
			if err != nil {
				return nil, fmt.Errorf("authkit: %s: %w", name, err)
			}
			a.providers[name] = p
		}
		for name, c := range cfg.OrganizationSSO {
			if _, exists := a.providers[name]; exists {
				return nil, fmt.Errorf("authkit: duplicate provider name %q", name)
			}
			if c.OrgID == "" || c.IssuerURL == "" {
				return nil, fmt.Errorf("authkit: SSO %s requires organization ID and issuer", name)
			}
			redirect := c.RedirectURL
			if redirect == "" {
				redirect = cfg.BaseURL + cfg.BasePath + "/callback/" + name
			}
			p, err := social.New(ctx, social.Config{Provider: name, IssuerURL: c.IssuerURL, AccountNamespace: c.OrgID, Scopes: c.Scopes, ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: redirect})
			if err != nil {
				return nil, fmt.Errorf("authkit: SSO %s: %w", name, err)
			}
			a.providers[name] = p
			a.ssoOrganizations[name] = c.OrgID
			if c.Domain != "" {
				domain, err := identity.NormalizeSSODomain(c.Domain)
				if err != nil {
					return nil, fmt.Errorf("authkit: SSO %s: %w", name, err)
				}
				a.ssoDomains[name] = domain
			}
		}
		a.membershipWriter, _ = cfg.Storage.Memberships.(membershipProvisioner)
	}
	for _, plugin := range cfg.Plugins {
		if plugin == nil {
			return nil, errors.New("authkit: nil plugin")
		}
		if err := plugin.apply(a); err != nil {
			return nil, err
		}
	}
	if a.Password == nil && a.Social == nil && a.Passkeys == nil {
		return nil, errors.New("authkit: enable at least one sign-in method")
	}
	if cfg.Storage.Migrate != nil {
		if err := cfg.Storage.Migrate(ctx); err != nil {
			return nil, fmt.Errorf("authkit: migrate: %w", err)
		}
	}
	for name, orgID := range a.ssoOrganizations {
		_, found, err := cfg.Storage.Organizations.GetByID(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("authkit: SSO %s organization lookup: %w", name, err)
		}
		if !found {
			return nil, fmt.Errorf("authkit: SSO %s organization %q does not exist", name, orgID)
		}
	}
	return a, nil
}

// Plugin configures an optional authkit feature.
type Plugin interface{ apply(*Auth) error }
type pluginFunc func(*Auth) error

func (f pluginFunc) apply(a *Auth) error { return f(a) }

func TwoFactor() Plugin {
	return pluginFunc(func(a *Auth) error {
		if a.config.Storage.MFA == nil || a.config.Signer == nil || a.Password == nil {
			return errors.New("authkit: two-factor requires email/password, an MFA store, and signer")
		}
		a.TwoFactor = identity.NewMFAService(a.config.Storage.MFA)
		if a.config.Storage.Recovery != nil {
			a.TwoFactor.WithRecoveryStore(a.config.Storage.Recovery)
		}
		a.Password = identity.NewLoginService(a.Sessions, a.config.Storage.Users, a.TwoFactor, a.config.Signer)
		return nil
	})
}

func Passkey(cfg gowebauthn.Config) Plugin {
	return pluginFunc(func(a *Auth) error {
		if a.config.Storage.Passkeys == nil || a.config.Storage.Flows == nil {
			return errors.New("authkit: passkey requires passkey and flow stores")
		}
		p, err := gowebauthn.New(cfg, a.config.Storage.Passkeys)
		if err != nil {
			return err
		}
		a.Passkeys = p
		return nil
	})
}

func Organization() Plugin {
	return pluginFunc(func(a *Auth) error {
		if a.config.Storage.Organizations == nil || a.config.Storage.Memberships == nil {
			return errors.New("authkit: organization requires organization and membership stores")
		}
		creator, ok := a.config.Storage.Organizations.(organizationCreator)
		if !ok {
			return errors.New("authkit: organization store must support CreateForUser")
		}
		a.orgCreator = creator
		a.Organizations = a.config.Storage.Organizations
		return nil
	})
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

const oauthStateTTL = 10 * time.Minute
