package identity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

// SSOConnection is an organization-owned OIDC connection. ClientSecret is
// returned only by the storage port; public API responses must omit it.
type SSOConnection struct {
	OrgID             string     `json:"orgId"`
	Domain            string     `json:"domain"`
	IssuerURL         string     `json:"issuerUrl"`
	ClientID          string     `json:"clientId"`
	ClientSecret      string     `json:"-"`
	VerificationToken string     `json:"verificationToken,omitempty"`
	VerifiedAt        *time.Time `json:"verifiedAt,omitempty"`
}

type SSOConnectionStore interface {
	SaveSSO(context.Context, SSOConnection) error
	GetSSOByOrg(context.Context, string) (SSOConnection, bool, error)
	GetSSOByDomain(context.Context, string) (SSOConnection, bool, error)
	ListVerifiedSSO(context.Context) ([]SSOConnection, error)
	VerifySSO(context.Context, string, string) error
	DeleteSSO(context.Context, string) error
}

// ManagedSSO owns configuration, domain proof and email discovery. Applications
// expose its methods through their own transport and mount Auth.Handler for OAuth.
type ManagedSSO struct {
	store     SSOConnectionStore
	key       []byte
	lookupTXT func(context.Context, string) ([]string, error)
}

var ErrSSOForbidden = errors.New("authkit: organization owner or admin required")

func NewManagedSSO(store SSOConnectionStore, key []byte) (*ManagedSSO, error) {
	if store == nil || len(key) != 32 {
		return nil, errors.New("authkit: managed SSO needs a store and 32-byte encryption key")
	}
	return &ManagedSSO{store: store, key: append([]byte(nil), key...), lookupTXT: net.DefaultResolver.LookupTXT}, nil
}

func ssoOwner(p Principal, orgID string) bool {
	if p.Kind != KindUser {
		return false
	}
	for _, m := range p.Memberships {
		if m.OrgID == orgID && (m.Role == "owner" || m.Role == "admin") {
			return true
		}
	}
	return false
}

func NormalizeSSODomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return "", errors.New("invalid email domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid email domain")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("invalid email domain")
			}
		}
	}
	return domain, nil
}

// Configure replaces an org's pending connection. Reconfiguration always
// requires fresh DNS proof; an old verified domain cannot silently change IdP.
func (m *ManagedSSO) Configure(ctx context.Context, p Principal, c SSOConnection) (SSOConnection, error) {
	if !ssoOwner(p, c.OrgID) {
		return SSOConnection{}, ErrSSOForbidden
	}
	domain, err := NormalizeSSODomain(c.Domain)
	if err != nil {
		return SSOConnection{}, err
	}
	u, err := url.Parse(c.IssuerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(c.IssuerURL) > 2048 {
		return SSOConnection{}, errors.New("authkit: issuer must be an HTTPS URL")
	}
	if c.ClientID == "" || c.ClientSecret == "" || len(c.ClientID) > 1024 || len(c.ClientSecret) > 4096 {
		return SSOConnection{}, errors.New("authkit: OIDC client ID and secret required")
	}
	proof := make([]byte, 24)
	if _, err := rand.Read(proof); err != nil {
		return SSOConnection{}, err
	}
	c.Domain = domain
	c.VerificationToken = "authkit-sso=" + base64.RawURLEncoding.EncodeToString(proof)
	c.VerifiedAt = nil
	secret, err := m.encrypt(c.ClientSecret)
	if err != nil {
		return SSOConnection{}, err
	}
	stored := c
	stored.ClientSecret = secret
	if err := m.store.SaveSSO(ctx, stored); err != nil {
		return SSOConnection{}, err
	}
	c.ClientSecret = ""
	return c, nil
}

// Verify proves control of _authkit-sso.<domain> via a TXT record. Only a
// verified domain participates in email discovery or authentication.
func (m *ManagedSSO) Verify(ctx context.Context, p Principal, orgID string) (SSOConnection, error) {
	if !ssoOwner(p, orgID) {
		return SSOConnection{}, ErrSSOForbidden
	}
	c, ok, err := m.store.GetSSOByOrg(ctx, orgID)
	if err != nil || !ok {
		return SSOConnection{}, errors.New("authkit: SSO connection not found")
	}
	records, err := m.lookupTXT(ctx, "_authkit-sso."+c.Domain)
	if err != nil {
		return SSOConnection{}, fmt.Errorf("authkit: DNS lookup failed: %w", err)
	}
	matched := false
	for _, record := range records {
		if record == c.VerificationToken {
			matched = true
			break
		}
	}
	if !matched {
		return SSOConnection{}, errors.New("authkit: DNS verification record missing")
	}
	if err := m.store.VerifySSO(ctx, orgID, c.VerificationToken); err != nil {
		return SSOConnection{}, err
	}
	now := time.Now().UTC()
	c.VerifiedAt = &now
	c.ClientSecret = ""
	return c, nil
}

func (m *ManagedSSO) Get(ctx context.Context, p Principal, orgID string) (SSOConnection, bool, error) {
	if !ssoOwner(p, orgID) {
		return SSOConnection{}, false, ErrSSOForbidden
	}
	c, ok, err := m.store.GetSSOByOrg(ctx, orgID)
	c.ClientSecret = ""
	return c, ok, err
}

func (m *ManagedSSO) Delete(ctx context.Context, p Principal, orgID string) error {
	if !ssoOwner(p, orgID) {
		return ErrSSOForbidden
	}
	return m.store.DeleteSSO(ctx, orgID)
}

// Discover returns only the organization ID. Its transport should use a
// generic no-match response so the endpoint cannot enumerate user accounts.
func (m *ManagedSSO) Discover(ctx context.Context, email string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil || addr.Address != strings.TrimSpace(email) {
		return "", errors.New("authkit: invalid email")
	}
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return "", errors.New("authkit: invalid email")
	}
	domain, err := NormalizeSSODomain(parts[1])
	if err != nil {
		return "", err
	}
	c, ok, err := m.store.GetSSOByDomain(ctx, domain)
	if err != nil || !ok {
		return "", err
	}
	return c.OrgID, nil
}

// Active returns only verified connections, with decrypted secrets for the
// AuthKit OAuth adapter. Callers must never serialize this result to clients.
func (m *ManagedSSO) Active(ctx context.Context) ([]SSOConnection, error) {
	connections, err := m.store.ListVerifiedSSO(ctx)
	if err != nil {
		return nil, err
	}
	for i := range connections {
		connections[i].ClientSecret, err = m.decrypt(connections[i].ClientSecret)
		if err != nil {
			return nil, err
		}
	}
	return connections, nil
}

// RuntimeConnection reads one connection for a gateway replica. A pending or
// deleted connection is unavailable even if that replica has an old OIDC cache.
func (m *ManagedSSO) RuntimeConnection(ctx context.Context, orgID string) (SSOConnection, bool, error) {
	c, ok, err := m.store.GetSSOByOrg(ctx, orgID)
	if err != nil || !ok || c.VerifiedAt == nil {
		return SSOConnection{}, false, err
	}
	c.ClientSecret, err = m.decrypt(c.ClientSecret)
	if err != nil {
		return SSOConnection{}, false, err
	}
	return c, true, nil
}

// PendingConnection is for a trusted server-side OIDC validation step. It
// returns the decrypted secret only to an authorized organization admin.
func (m *ManagedSSO) PendingConnection(ctx context.Context, p Principal, orgID string) (SSOConnection, error) {
	if !ssoOwner(p, orgID) {
		return SSOConnection{}, ErrSSOForbidden
	}
	c, ok, err := m.store.GetSSOByOrg(ctx, orgID)
	if err != nil {
		return SSOConnection{}, err
	}
	if !ok {
		return SSOConnection{}, errors.New("authkit: SSO connection not found")
	}
	c.ClientSecret, err = m.decrypt(c.ClientSecret)
	return c, err
}

func (m *ManagedSSO) encrypt(value string) (string, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(value), nil)), nil
}

func (m *ManagedSSO) decrypt(value string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", errors.New("authkit: invalid encrypted secret")
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
