package authkit

import (
	"context"
	"strings"

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

// ValidateManagedSSO discovers the configured OIDC issuer and checks that its
// client and callback settings can build an AuthKit provider before activation.
func ValidateManagedSSO(ctx context.Context, manager *ManagedSSO, principal identity.Principal, orgID, redirectURL string) error {
	c, err := manager.PendingConnection(ctx, principal, orgID)
	if err != nil {
		return err
	}
	_, err = social.New(ctx, social.Config{Provider: "org_" + strings.TrimPrefix(orgID, "org_"), IssuerURL: c.IssuerURL,
		AccountNamespace: orgID, ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: redirectURL})
	return err
}
