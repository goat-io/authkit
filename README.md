# authkit

Authkit is a Go authentication toolkit you configure once and mount as an HTTP handler. It includes email/password login, social sign-in, sessions, and optional two-factor, passkey, organization, team, and organization-owned OIDC SSO features. The default PostgreSQL adapter creates and migrates its tables; the core services remain available for custom storage and frameworks.

Requires Go 1.25 or newer.

```sh
go get github.com/goat-io/authkit@latest
```

Teams and managed SSO require `v0.2.0` or newer. Pin a specific tag instead of `@latest` when you need reproducible builds.

## One-config setup

Set `DATABASE_URL`, provider credentials, and `AUTHKIT_ED25519_SEED` (a persistent, base64-encoded 32-byte Ed25519 seed for the two-factor challenge signer). The example runs at `http://localhost:8080`; use an HTTPS `BaseURL` in production.

```go
package main

import (
    "context"
    "encoding/base64"
    "log"
    "net/http"
    "os"

    "github.com/goat-io/authkit"
    "github.com/goat-io/authkit/token/eddsa"
    "github.com/goat-io/authkit/webauthn/gowebauthn"
    "github.com/jackc/pgx/v5/pgxpool"
)

func main() {
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { log.Fatal(err) }
    defer pool.Close()

    seed, err := base64.StdEncoding.DecodeString(os.Getenv("AUTHKIT_ED25519_SEED"))
    if err != nil { log.Fatal(err) }
    signer, err := eddsa.New(seed)
    if err != nil { log.Fatal(err) }

    auth, err := authkit.New(ctx, authkit.Config{
        BaseURL: "http://localhost:8080",
        Storage: authkit.Postgres(pool),
        Signer: signer,
        EmailAndPassword: authkit.EmailAndPassword{Enabled: true},
        SocialProviders: map[string]authkit.SocialProvider{
            "google": {
                ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
                ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
            },
            "github": {
                ClientID: os.Getenv("GITHUB_CLIENT_ID"),
                ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
            },
        },
        Plugins: []authkit.Plugin{
            authkit.TwoFactor(),
            authkit.Passkey(gowebauthn.Config{
                RPID: "localhost", RPDisplayName: "My App",
                RPOrigins: []string{"http://localhost:8080"},
            }),
            authkit.Organization(),
        },
    })
    if err != nil { log.Fatal(err) }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", auth.Handler())
    mux.Handle("GET /me", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        principal, _ := authkit.PrincipalFrom(r.Context())
        if !principal.Authenticated() {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        _, _ = w.Write([]byte(principal.Subject))
    })))
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

`authkit.New` validates the configuration, discovers configured OpenID providers, wires the services, and runs the PostgreSQL migration. `Auth.Handler()` mounts the selected routes. `Auth.Middleware` accepts its session cookie or a Bearer token and puts an `identity.Principal` in the request context; your application checks roles, scopes, organization membership, and step-up requirements.

| Enabled feature | Routes under `/api/auth` |
| --- | --- |
| Email/password | `POST /sign-up/email`, `POST /sign-in/email` |
| Social providers | `GET /sign-in/social/{provider}`, `GET or POST /callback/{provider}`, `POST /link/social/{provider}` |
| Organization SSO | `GET /sign-in/sso/{connection}`, `GET or POST /callback/{connection}`, `POST /link/sso/{connection}` |
| Two-factor plugin | `POST /two-factor/enroll`, `POST /two-factor/confirm`, `POST /two-factor/complete` |
| Passkey plugin | `POST /passkey/register/begin`, `/register/finish`, `/sign-in/begin`, `/sign-in/finish` |
| Organization plugin | `POST /organization/create`, `GET /organization/list` |
| Teams (when `Storage.Teams` is set) | `GET/POST /organization/{orgId}/teams`, `GET/DELETE /organization/{orgId}/teams/{teamId}`, `GET /organization/{orgId}/teams/{teamId}/members`, `PUT/DELETE /organization/{orgId}/teams/{teamId}/members/{userId}` |
| Always | `GET /session`, `POST /sign-out` |

Email/password and passkey requests use JSON. The passkey `begin` routes return browser credential options; the `finish` routes accept the browser's raw credential response JSON. Social start and link routes redirect the browser to the provider. `POST /link/social/{provider}` requires an authenticated session and an `Origin` header matching `BaseURL` (a same-origin HTML form works). The callback sets an HTTP-only session cookie and redirects to `BaseURL`. On HTTPS, session and OAuth flow cookies use the host-bound `__Host-` prefix. Cookie-authenticated mutations reject a mismatched `Origin` or a same-site/cross-site `Sec-Fetch-Site` value when `Origin` is absent.

When two-factor is enabled and a user has enrolled TOTP, password, social, and passkey sign-ins return an MFA challenge instead of a session. Browser flows store that challenge in a short-lived HTTP-only cookie and redirect with `?authkit_mfa=required` where needed. Submit `{"code":"123456"}` to `POST /two-factor/complete`; an API client can also pass the challenge in the JSON body. Only the completed challenge creates a session.

## Social providers

Use each provider's name as a key in `SocialProviders`. Callback URLs default to `BaseURL + /api/auth/callback/{provider}`; set `RedirectURL` to override. Register the exact callback URL with the provider.

| Provider | Additional setup |
| --- | --- |
| [Google](https://developers.google.com/identity/openid-connect/openid-connect) | OAuth web client ID and secret. |
| [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) | OAuth app client ID and secret. Authkit requests `read:user` and `user:email` and uses the stable GitHub user ID. |
| [Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) | Entra client ID and secret plus `MicrosoftTenant` set to a specific tenant GUID. Multi-tenant authorities are not supported yet. |
| [LinkedIn](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2) | Client ID and secret; enable **Sign In with LinkedIn using OpenID Connect**. |
| [Apple](https://developer.apple.com/documentation/signinwithapple/configuring-your-environment-for-sign-in-with-apple) | App ID or Services ID as `ClientID`; supply `ClientSecret` or `AppleTeamID`, `AppleKeyID`, and a P-256 `ApplePrivateKey`. Web callback URLs must use HTTPS. |

Google, Microsoft, LinkedIn, and Apple use verified OpenID Connect ID tokens. GitHub uses its OAuth code flow and authenticated user API. Authkit keys accounts by `(provider, subject)`, never by email. An existing email produces `identity.ErrEmailInUse` until the signed-in user explicitly links that provider. PostgreSQL stores callback and passkey challenges as one-time, expiring flows so multiple server instances can share them.

For native iOS sign-in, verify a Google, Microsoft, or Apple ID token with `auth.SignInWithIDToken(ctx, provider, rawToken, expectedNonce)`. Generate and retain a one-time nonce for that attempt. If the native app uses a different client ID from the web flow, add it to that provider's `NativeClientIDs`; the web flow keeps using `ClientID`. The result contains either `Session` or an MFA `Challenge`. LinkedIn and GitHub use the authorization-code flow.

## Organization SSO (bring your own identity provider)

An organization can use its own **OpenID Connect (OIDC)** provider. Create the organization first, then register a connection at application startup:

```go
OrganizationSSO: map[string]authkit.OIDCProvider{
    "acme": {
        OrgID:        "org_acme",
        IssuerURL:    "https://login.acme.example/realms/employees",
        ClientID:     os.Getenv("ACME_OIDC_CLIENT_ID"),
        ClientSecret: os.Getenv("ACME_OIDC_CLIENT_SECRET"),
    },
},
```

Register `https://your-app.example/api/auth/callback/acme` as the redirect URI at the identity provider, then direct users to `GET /api/auth/sign-in/sso/acme`. Authkit discovers the issuer's OIDC endpoints and signing keys, uses authorization code with PKCE, and checks the signed ID token's issuer, audience, expiry, and nonce. After successful verification, it adds the user to `org_acme` with the `member` role; an existing role is preserved. If the email belongs to an existing account, the user must sign in first and explicitly link it with `POST /api/auth/link/sso/acme` (same-origin request). The connection name, issuer, and organization ID isolate account identities, so reusing a name for another issuer or organization does not silently transfer accounts.

For organization-managed setup, `authkit.NewManagedSSO(postgres.NewSSOConnections(pool), key)` manages encrypted client secrets and DNS ownership proof. Your application supplies its own admin and email-discovery endpoints, then loads verified connections into `Config.OrganizationSSO`. Use `authkit.SSOProviderName(orgID)` for a stable callback name and set `OIDCProvider.Domain` so sign-in requires a provider-verified email in that domain. A connection change must be reverified and the `Auth` instance refreshed; managed connections are not hot-loaded automatically. See the [organizations and SSO guide](docs/organizations.md) for the complete setup and route examples.

The issuer must be HTTPS and serve standard OIDC discovery. Plain OAuth 2.0 without OIDC identity tokens and SAML are separate integrations. An application should also rate-limit the public email-discovery endpoint and refresh its active-provider cache after connection changes.

## Teams

`authkit.Postgres(pool)` includes the team store, so mounting `Auth.Handler()` enables team routes. Teams belong to one organization, have a unique slug within that organization, and support `owner`, `admin`, and `member` roles. Organization owners/admins can create teams and see all teams; other organization members see only teams they belong to. Team owners/admins and organization owners/admins can manage membership, but the team owner cannot be removed or downgraded through the member routes. Users must already belong to the organization before they can be added to a team. See the [organizations and SSO guide](docs/organizations.md) for requests and authorization rules.

## Lower-level packages

The configured handler is optional. `identity` defines the session, machine credential, MFA, organization, and storage interfaces. `social` exposes provider flows; `webauthn/gowebauthn` exposes passkey ceremonies; `token/eddsa` signs machine JWTs and MFA challenges. `store/postgres` supplies the schema and store implementations. `transport/nethttp` and `transport/fiber` remain available when you own the HTTP routes.

For machine clients, create `identity.NewCredentialService(postgres.NewCredentials(pool), signer, ttl)`. `Mint` returns a durable secret once; `Exchange` trades it for a short-lived JWT. Revoking the secret stops future exchanges, while already-issued JWTs remain valid until expiry. The `Authenticator` resolves machine JWTs, user sessions, and an optional admin token to one `Principal`.

## Releases

Go modules are distributed from Git tags; there is no separate package upload. CI runs module checks, vet, and the race-enabled test suite against PostgreSQL for pull requests, `main`, and version tags. After a version tag passes, CI creates a GitHub release. To publish the next version, merge the changes to `main`, then create and push an immutable semantic version tag. Consumers can install `@latest` and keep the version recorded in their `go.mod`, or request a specific tag.

The `v0` series is for refining the public API. A future `v1.0.0` will signal a stable compatibility commitment; breaking changes after that require a new major module path such as `/v2`.

## Operational notes

- Set an HTTPS `BaseURL` in production and keep provider secrets and the Ed25519 seed stable and private. The session cookie is HTTP-only and `Secure` when `BaseURL` uses HTTPS.
- Add rate limits and email verification for public password sign-up. Authkit currently creates an account immediately from the submitted email.
- Run `postgres.NewSessions(pool).PurgeExpired(ctx)` and `postgres.NewFlows(pool).PurgeExpired(ctx)` periodically. Expired records cannot authenticate or complete a flow, but periodic cleanup reclaims storage.
- TOTP secrets are stored in plaintext by the PostgreSQL adapter. Protect database access and backups. Recovery codes and session tokens are stored as hashes.

Run the tests with `go test ./...`. PostgreSQL tests use `AUTHKIT_TEST_DATABASE_URL` when set and skip when their database is unreachable.

[MIT license](LICENSE)
