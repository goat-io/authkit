# Organizations, teams, and SSO

Authkit stores organization membership separately from team membership. An organization owner can create teams and configure an OIDC connection; a team owner can manage that team's members. `authkit.Postgres(pool)` supplies the organization, team, and SSO stores and migrates their tables when passed to `authkit.New`.

The APIs on this page were added after `v0.1.0`. Until the next tagged release, use `go get github.com/goat-io/authkit@main` to try them, or pin the resulting commit-based version.

## Teams

Enable `authkit.Organization()` to expose organization create/list routes. With `authkit.Postgres(pool)`, team routes are enabled because `Storage.Teams` is populated. A custom storage adapter must implement `identity.TeamStore` and set `Storage.Teams`. Team routes require an authenticated user; the PostgreSQL store checks the actor's current membership during writes.

Create a team in an existing organization:

```http
POST /api/auth/organization/{orgId}/teams
Content-Type: application/json

{"name":"Engineering","slug":"engineering"}
```

`slug` is optional and is derived from `name` when omitted. It must use lowercase letters, numbers, or hyphens and is unique within the organization. The response is `201` with `{"team":{"id":"team_...","orgId":"...","name":"Engineering","slug":"engineering","createdAt":"..."}}`. The creator becomes the team owner.

| Method | Route under `/api/auth` | Result |
| --- | --- | --- |
| `GET` | `/organization/{orgId}/teams` | `{"teams":[...]}` |
| `POST` | `/organization/{orgId}/teams` | Create a team; `{"team":...}` |
| `GET` | `/organization/{orgId}/teams/{teamId}` | `{"team":...}` |
| `DELETE` | `/organization/{orgId}/teams/{teamId}` | Delete the team; `204` |
| `GET` | `/organization/{orgId}/teams/{teamId}/members` | `{"members":[{"teamId":"...","userId":"...","role":"..."}]}` |
| `PUT` | `/organization/{orgId}/teams/{teamId}/members/{userId}` | Add or update a member with `{"role":"member"}` or `{"role":"admin"}`; `204` |
| `DELETE` | `/organization/{orgId}/teams/{teamId}/members/{userId}` | Remove a member; `204` |

Organization `owner`/`admin` users can create and delete teams, see all teams, and manage team members. Other organization members see only teams they belong to. A team `owner` can delete that team; team `owner`/`admin` users can manage its members. The target user must already be an organization member. The membership routes cannot remove or downgrade the team owner. For application authorization, query `identity.TeamStore` for current team membership; organization membership in a session is not a substitute for a team role.

## Organization-owned OIDC SSO

Authkit offers two ways to register an OIDC connection. `Config.OrganizationSSO` is a static map configured by the application operator. `authkit.NewManagedSSO` is a server-side service for an organization owner or admin to configure a connection, prove domain ownership, and discover verified domains. Managed SSO does **not** add admin or discovery HTTP routes to `Auth.Handler()` and does not hot-reload `Config.OrganizationSSO`; your application supplies those routes and refreshes its `Auth` instance after connection changes.

For a static connection, create the organization first, then add an entry to `Config.OrganizationSSO` with `OrgID`, HTTPS `IssuerURL`, `ClientID`, `ClientSecret`, and optionally `Domain`, `Scopes`, and `RedirectURL`. When `Domain` is set, Authkit accepts only a provider-verified email at that domain before linking or granting organization membership. The default callback is `BaseURL + BasePath + "/callback/" + connectionName`.

For organization-managed connections, use this sequence:

1. Create a persistent, private 32-byte key shared by every server instance. After `postgres.Migrate(ctx, pool)`, create a manager with `manager, err := authkit.NewManagedSSO(postgres.NewSSOConnections(pool), key)`.
2. Authenticate the organization owner or admin and pass their `identity.Principal` to `manager.Configure(ctx, principal, authkit.SSOConnection{OrgID: orgID, Domain: "acme.example", IssuerURL: issuer, ClientID: clientID, ClientSecret: clientSecret})`. The returned connection omits the secret and contains `VerificationToken`.
3. Register `BaseURL + BasePath + "/callback/" + authkit.SSOProviderName(orgID)` with the IdP. Optionally call `authkit.ValidateManagedSSO(ctx, manager, principal, orgID, callbackURL)` from a trusted server to check OIDC discovery and build the provider before activation. This cannot prove the client secret works; that requires an actual sign-in.
4. Ask the organization to publish the returned token as a TXT record at `_authkit-sso.acme.example`. Call `manager.Verify(ctx, principal, orgID)` after DNS has propagated. Only a verified connection participates in `Discover` or `Active`.
5. Load `manager.Active(ctx)` into `Config.OrganizationSSO` using the same provider name, then construct a new `Auth` and mount its handler:

```go
connections, err := manager.Active(ctx)
if err != nil { return err }

providers := make(map[string]authkit.OIDCProvider, len(connections))
for _, c := range connections {
    name := authkit.SSOProviderName(c.OrgID)
    providers[name] = authkit.OIDCProvider{
        OrgID: c.OrgID, Domain: c.Domain, IssuerURL: c.IssuerURL,
        ClientID: c.ClientID, ClientSecret: c.ClientSecret,
    }
}

auth, err := authkit.New(ctx, authkit.Config{
    BaseURL: baseURL,
    Storage: authkit.Postgres(pool),
    EmailAndPassword: authkit.EmailAndPassword{Enabled: true},
    OrganizationSSO: providers,
    Plugins: []authkit.Plugin{authkit.Organization()},
})
if err != nil { return err }
```

`Active` contains decrypted client secrets and is only for trusted server code. `Get` returns redacted connection metadata to an authorized owner/admin. `PendingConnection` and `RuntimeConnection` return decrypted secrets for trusted server integrations; never serialize them to clients. `Discover(ctx, email)` returns an organization ID when the email's domain has a verified connection. Put a rate limit and a generic no-match response around any public discovery endpoint so it cannot enumerate accounts.

After loading the connection, send users to `GET /api/auth/sign-in/sso/{name}`. Existing users can link it with `POST /api/auth/link/sso/{name}` from the application's origin. Successful OIDC sign-in adds an organization `member` role without downgrading an existing role. Authkit scopes the social identity to the connection name, issuer, and organization ID, and checks the signed ID token's issuer, audience, expiry, and nonce.

SSO sign-in does not assign a team. Add the user to a team separately through the team membership route or `identity.TeamStore` after your application has determined their team access.

`Configure` replaces the pending connection and clears verification, even when only the issuer, client, or domain changes. `Delete` removes it. After either operation, rebuild and swap the `Auth` handler on **every** server instance so a previously loaded connection is no longer offered. `RuntimeConnection` lets a gateway check current verification state when it uses a cached provider, but `Auth.Handler()` does not call it automatically. Keep the encryption key stable across restarts; losing it prevents decryption of existing client secrets.

The OIDC issuer must support standard discovery over HTTPS. Plain OAuth without an ID token and SAML are not handled by these routes. On HTTPS, Authkit uses host-bound `__Host-` session and OAuth flow cookies. Cookie-authenticated mutations require the application's origin (or same-origin fetch metadata when `Origin` is absent); OAuth callbacks are bound to one-time flow state instead.
