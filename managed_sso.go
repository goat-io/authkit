package authkit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/goat-io/authkit/identity"
	"github.com/goat-io/authkit/social"
)

// Managed SSO is implemented in the identity layer so applications can use it
// independently of the HTTP adapter.
type SSOConnection = identity.SSOConnection
type SSOConnectionStore = identity.SSOConnectionStore
type ManagedSSO = identity.ManagedSSO

var NewManagedSSO = identity.NewManagedSSO
var ErrSSOForbidden = identity.ErrSSOForbidden

// SSOProviderName returns a stable, URL-safe provider key for an organization.
// Use the same key when building Config.OrganizationSSO and its callback URL.
func SSOProviderName(orgID string) string {
	sum := sha256.Sum256([]byte(orgID))
	return "sso_" + hex.EncodeToString(sum[:16])
}

// ValidateManagedSSO discovers the configured OIDC issuer and checks that its
// client and callback settings can build an AuthKit provider before activation.
func ValidateManagedSSO(ctx context.Context, manager *ManagedSSO, principal identity.Principal, orgID, redirectURL string) error {
	c, err := manager.PendingConnection(ctx, principal, orgID)
	if err != nil {
		return err
	}
	_, err = social.New(ctx, social.Config{Provider: SSOProviderName(orgID), IssuerURL: c.IssuerURL,
		AccountNamespace: orgID, ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: redirectURL})
	return err
}
