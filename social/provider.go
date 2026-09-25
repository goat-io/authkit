// Package social provides OpenID Connect sign-in for Google, Microsoft,
// LinkedIn, and Apple. Applications own the HTTP redirect/callback handlers and
// must store each pending authorization request securely until completion.
package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/goat-io/authkit/identity"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	Google    = "google"
	Microsoft = "microsoft"
	LinkedIn  = "linkedin"
	Apple     = "apple"
	GitHub    = "github"
)

var ErrInvalidCallback = errors.New("invalid social sign-in callback")

var tenantIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var providerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// Config is one provider registration. MicrosoftTenant must be a specific
// tenant ID; multi-tenant authorities need additional
// issuer and signing-key validation and are deliberately not accepted here.
type Config struct {
	Provider         string
	IssuerURL        string // for a custom OpenID Connect provider
	Scopes           []string
	AccountNamespace string // additional account isolation, such as an organization ID
	ClientID         string
	NativeClientIDs  []string // extra audiences for native ID-token verification
	ClientSecret     string
	RedirectURL      string
	MicrosoftTenant  string
	AppleTeamID      string
	AppleKeyID       string
	ApplePrivateKey  *ecdsa.PrivateKey
}

// Pending contains the state, nonce, and PKCE verifier for one sign-in attempt.
// Persist it server-side or in an authenticated, encrypted, short-lived cookie.
// It is single-use: delete it after any callback attempt.
type Pending struct {
	State        string
	Nonce        string
	CodeVerifier string
	CreatedAt    time.Time
}

type Provider struct {
	config          Config
	accountProvider string
	oauth           oauth2.Config
	verifier        *oidc.IDTokenVerifier
	nativeVerifiers []*oidc.IDTokenVerifier
}

// New discovers the provider's endpoints and verification keys. For Apple,
// provide either ClientSecret or TeamID, KeyID, and a P-256 private key.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("social: client ID and redirect URL are required")
	}
	if !providerIDPattern.MatchString(cfg.Provider) {
		return nil, errors.New("social: invalid provider ID")
	}
	issuer := ""
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	accountProvider := cfg.Provider
	if cfg.IssuerURL != "" {
		parsed, err := url.Parse(cfg.IssuerURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, errors.New("social: custom OIDC issuer must be an HTTPS URL without query or fragment")
		}
		switch cfg.Provider {
		case Google, Microsoft, LinkedIn, Apple, GitHub:
			return nil, errors.New("social: custom OIDC provider needs its own provider ID")
		}
		issuer = cfg.IssuerURL
		scopes = append(scopes, cfg.Scopes...)
		sum := sha256.Sum256([]byte(issuer + "\x00" + cfg.AccountNamespace))
		accountProvider = cfg.Provider + "@" + base64.RawURLEncoding.EncodeToString(sum[:])
	} else {
		switch cfg.Provider {
		case Google:
			issuer = "https://accounts.google.com"
		case Microsoft:
			if !tenantIDPattern.MatchString(cfg.MicrosoftTenant) {
				return nil, errors.New("social: Microsoft requires a specific tenant GUID")
			}
			issuer = "https://login.microsoftonline.com/" + cfg.MicrosoftTenant + "/v2.0"
		case LinkedIn:
			issuer = "https://www.linkedin.com/oauth"
		case Apple:
			issuer = "https://appleid.apple.com"
			scopes = []string{oidc.ScopeOpenID, "email", "name"}
			if cfg.ClientSecret == "" {
				if cfg.AppleTeamID == "" || cfg.AppleKeyID == "" || cfg.ApplePrivateKey == nil || cfg.ApplePrivateKey.Curve != elliptic.P256() {
					return nil, errors.New("social: Apple client secret or P-256 signing key configuration is required")
				}
			}
		case GitHub:
			scopes = []string{"read:user", "user:email"}
		default:
			return nil, fmt.Errorf("social: unsupported provider %q", cfg.Provider)
		}
	}
	if cfg.Provider != Apple && cfg.ClientSecret == "" {
		return nil, errors.New("social: client secret is required")
	}
	var endpoint oauth2.Endpoint
	var verifier *oidc.IDTokenVerifier
	var nativeVerifiers []*oidc.IDTokenVerifier
	if cfg.Provider == GitHub {
		endpoint = oauth2.Endpoint{AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token", AuthStyle: oauth2.AuthStyleInParams}
	} else {
		provider, err := oidc.NewProvider(ctx, issuer)
		if err != nil {
			return nil, err
		}
		endpoint = provider.Endpoint()
		verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
		nativeVerifiers = append(nativeVerifiers, verifier)
		for _, clientID := range cfg.NativeClientIDs {
			if clientID == "" {
				return nil, errors.New("social: native client ID cannot be empty")
			}
			nativeVerifiers = append(nativeVerifiers, provider.Verifier(&oidc.Config{ClientID: clientID}))
		}
	}
	if cfg.Provider == Apple || cfg.Provider == LinkedIn {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	return &Provider{config: cfg, accountProvider: accountProvider, oauth: oauth2.Config{
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: scopes,
	}, verifier: verifier, nativeVerifiers: nativeVerifiers}, nil
}

// Begin returns a provider authorization URL and the pending request to retain
// until the callback. The caller must bind Pending to the initiating browser.
func (p *Provider) Begin() (string, Pending, error) {
	state, err := randomString()
	if err != nil {
		return "", Pending{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return "", Pending{}, err
	}
	verifier := oauth2.GenerateVerifier()
	pending := Pending{State: state, Nonce: nonce, CodeVerifier: verifier, CreatedAt: time.Now().UTC()}
	opts := []oauth2.AuthCodeOption{}
	// LinkedIn's OIDC implementation does not reliably echo nonce in ID tokens.
	// Its code flow is still bound to the browser by state and code redemption.
	if p.config.Provider != LinkedIn && p.config.Provider != GitHub {
		opts = append(opts, oidc.Nonce(nonce))
	}
	if p.config.Provider != Apple && p.config.Provider != LinkedIn {
		opts = append(opts, oauth2.S256ChallengeOption(verifier))
	}
	if p.config.Provider == Apple {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	return p.oauth.AuthCodeURL(state, opts...), pending, nil
}

// Complete redeems a callback code and verifies its signed ID token, audience,
// issuer, expiry, and nonce. Validate and consume Pending before using it again.
func (p *Provider) Complete(ctx context.Context, pending Pending, state, code string) (identity.SocialIdentity, error) {
	if code == "" || state == "" || pending.State == "" || pending.Nonce == "" ||
		time.Since(pending.CreatedAt) > 10*time.Minute || pending.CreatedAt.After(time.Now().Add(time.Minute)) ||
		subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		return identity.SocialIdentity{}, ErrInvalidCallback
	}
	conf := p.oauth
	if p.config.Provider == Apple && p.config.ClientSecret == "" {
		secret, err := p.appleClientSecret()
		if err != nil {
			return identity.SocialIdentity{}, err
		}
		conf.ClientSecret = secret
	}
	opts := []oauth2.AuthCodeOption{}
	if p.config.Provider != Apple && p.config.Provider != LinkedIn {
		if pending.CodeVerifier == "" {
			return identity.SocialIdentity{}, ErrInvalidCallback
		}
		opts = append(opts, oauth2.VerifierOption(pending.CodeVerifier))
	}
	token, err := conf.Exchange(ctx, code, opts...)
	if err != nil {
		return identity.SocialIdentity{}, err
	}
	if p.config.Provider == GitHub {
		return p.githubIdentity(ctx, token)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return identity.SocialIdentity{}, ErrInvalidCallback
	}
	return p.verifyIDToken(ctx, raw, pending.Nonce, p.config.Provider != LinkedIn, []*oidc.IDTokenVerifier{p.verifier})
}

// VerifyIDToken supports native mobile flows that deliver an ID token directly.
// expectedNonce must be the nonce generated and retained by the application for
// that one native sign-in attempt. Use a separate Provider per client ID/audience.
func (p *Provider) VerifyIDToken(ctx context.Context, raw, expectedNonce string) (identity.SocialIdentity, error) {
	if p.config.Provider == LinkedIn || p.config.Provider == GitHub {
		return identity.SocialIdentity{}, ErrInvalidCallback
	}
	verifiers := p.nativeVerifiers
	if len(verifiers) == 0 {
		verifiers = []*oidc.IDTokenVerifier{p.verifier}
	}
	return p.verifyIDToken(ctx, raw, expectedNonce, true, verifiers)
}

func (p *Provider) verifyIDToken(ctx context.Context, raw, expectedNonce string, requireNonce bool, verifiers []*oidc.IDTokenVerifier) (identity.SocialIdentity, error) {
	if raw == "" || (requireNonce && expectedNonce == "") {
		return identity.SocialIdentity{}, ErrInvalidCallback
	}
	var token *oidc.IDToken
	var err error
	for _, verifier := range verifiers {
		token, err = verifier.Verify(ctx, raw)
		if err == nil {
			break
		}
	}
	if err != nil {
		return identity.SocialIdentity{}, err
	}
	if (requireNonce && subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(expectedNonce)) != 1) || token.Subject == "" {
		return identity.SocialIdentity{}, ErrInvalidCallback
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := token.Claims(&claims); err != nil {
		return identity.SocialIdentity{}, err
	}
	verified := claims.EmailVerified == true || claims.EmailVerified == "true"
	providerID := p.accountProvider
	if providerID == "" {
		providerID = p.config.Provider
	}
	return identity.SocialIdentity{Provider: providerID, Subject: token.Subject,
		Email: claims.Email, EmailVerified: verified, DisplayName: claims.Name}, nil
}

func (p *Provider) appleClientSecret() (string, error) {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer: p.config.AppleTeamID, Subject: p.config.ClientID,
		Audience: jwt.ClaimStrings{"https://appleid.apple.com"},
		IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	})
	token.Header["kid"] = p.config.AppleKeyID
	return token.SignedString(p.config.ApplePrivateKey)
}

func (p *Provider) githubIdentity(ctx context.Context, token *oauth2.Token) (identity.SocialIdentity, error) {
	client := p.oauth.Client(ctx, token)
	get := func(url string, into any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "authkit")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("social: GitHub API returned %d", resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
	}
	var user struct {
		ID    int64  `json:"id"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err := get("https://api.github.com/user", &user); err != nil {
		return identity.SocialIdentity{}, err
	}
	if user.ID <= 0 {
		return identity.SocialIdentity{}, ErrInvalidCallback
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := get("https://api.github.com/user/emails", &emails); err != nil {
		return identity.SocialIdentity{}, err
	}
	name := user.Name
	if name == "" {
		name = user.Login
	}
	person := identity.SocialIdentity{Provider: GitHub, Subject: strconv.FormatInt(user.ID, 10), DisplayName: name}
	for _, email := range emails {
		if email.Primary && email.Verified && email.Email != "" {
			person.Email, person.EmailVerified = email.Email, true
			break
		}
	}
	return person, nil
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
