<div align="center">

# AuthKit

**Authentication for Go, configured once and owned by your app.**

Email and password, social sign-in, passkeys, two-factor authentication, organizations, teams, and OIDC SSO—wired through one Go config.

[![Go Reference](https://pkg.go.dev/badge/github.com/goat-io/authkit.svg)](https://pkg.go.dev/github.com/goat-io/authkit)
[![CI](https://github.com/goat-io/authkit/actions/workflows/ci.yml/badge.svg)](https://github.com/goat-io/authkit/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Get started](#get-started) · [Explore features](#what-you-can-build) · [Organizations and SSO](docs/organizations.md) · [Releases](https://github.com/goat-io/authkit/releases)

</div>

AuthKit gives Go applications a ready-to-mount `net/http` auth handler and a PostgreSQL adapter. Configure the methods your product needs; AuthKit wires the services, migrates its tables, and exposes the corresponding routes. Your users, sessions, and organization data stay in your database. The core interfaces also let you supply another storage adapter or own the HTTP layer.

## One config, room to grow

```go
auth, err := authkit.New(ctx, authkit.Config{
    BaseURL: "https://app.example.com",
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
            RPID: "app.example.com",
            RPDisplayName: "My App",
            RPOrigins: []string{"https://app.example.com"},
        }),
        authkit.Organization(),
    },
})
if err != nil { log.Fatal(err) }

mux.Handle("/api/auth/", auth.Handler())
```

`pool` is a `*pgxpool.Pool`; `signer` is an `identity.Signer` backed by a persistent Ed25519 seed. Register `https://app.example.com/api/auth/callback/google` and `https://app.example.com/api/auth/callback/github` with the respective providers. Enable only the providers and plugins you have configured. For a runnable example that needs only PostgreSQL, see [Get started](#get-started).

## What you can build

| Capability | Included behavior |
| --- | --- |
| **Everyday sign-in** | Email/password, opaque sessions, sign-out, and session middleware. |
| **Social login** | Google, GitHub, Microsoft, LinkedIn, and Apple. Web redirects and callbacks are included; Google, Microsoft, and Apple also support verified native ID tokens. |
| **Stronger authentication** | Optional TOTP two-factor authentication, recovery codes, and WebAuthn passkeys. |
| **Multi-tenant apps** | Organizations, owner/admin/member roles, and organization-owned teams with their own membership roles. |
| **Bring-your-own SSO** | Per-organization OIDC connections. The managed SSO service adds domain ownership proof and encrypted client secrets. |
| **Machine clients** | Lower-level credentials that exchange for short-lived Ed25519-signed JWTs. |

The default HTTP handler is built for `net/http`. The [`identity`](identity) package exposes the services and storage interfaces; [`store/postgres`](store/postgres) is the included adapter. [`transport/fiber`](transport/fiber) and [`transport/nethttp`](transport/nethttp) provide lower-level middleware if you own your routes.

## Get started

Requires **Go 1.25+** and PostgreSQL for the included adapter.

```sh
go get github.com/goat-io/authkit@latest
```

Set `DATABASE_URL` to a PostgreSQL connection string, then start with email/password and organizations. `authkit.New` applies the PostgreSQL schema and mounts the enabled routes; no provider credentials or signing key are needed for this minimal setup.

<details>
<summary>Complete minimal server</summary>

<!-- readme-example:start -->
```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "github.com/goat-io/authkit"
    "github.com/jackc/pgx/v5/pgxpool"
)

func main() {
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { log.Fatal(err) }
    defer pool.Close()

    auth, err := authkit.New(ctx, authkit.Config{
        BaseURL: "http://localhost:8080",
        Storage: authkit.Postgres(pool),
        EmailAndPassword: authkit.EmailAndPassword{Enabled: true},
        Plugins: []authkit.Plugin{authkit.Organization()},
    })
    if err != nil { log.Fatal(err) }

    mux := http.NewServeMux()
    mux.Handle("/api/auth/", auth.Handler())
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```
<!-- readme-example:end -->

</details>

The server exposes `POST /api/auth/sign-up/email`, `POST /api/auth/sign-in/email`, `GET /api/auth/session`, and `POST /api/auth/sign-out`. Add social providers or plugins to the config as your product grows. For protected application routes, wrap your handler with `auth.Middleware` and inspect `authkit.PrincipalFrom(r.Context())` for the authenticated user, scopes, and organization memberships.

## Social sign-in and SSO

Configure a social provider by name in `SocialProviders` and register its callback URL, `BaseURL + /api/auth/callback/{provider}`. Google, Microsoft, LinkedIn, and Apple use OpenID Connect ID tokens; GitHub uses its OAuth flow and authenticated user API. For Microsoft, set a specific `MicrosoftTenant` GUID. For Apple web sign-in, use an HTTPS `BaseURL` and supply a client secret or Apple signing key details.

For a customer's own identity provider, add an OIDC connection to `OrganizationSSO` with its organization ID, issuer URL, client ID, and secret. Users start at `/api/auth/sign-in/sso/{connection}`. Successful sign-in grants organization membership without replacing an existing role. The [organizations and SSO guide](docs/organizations.md) covers static connections, organization-managed registration, DNS proof, teams, and the application-owned admin endpoints.

Social accounts are keyed by provider and subject. An existing account with the same email is **not** silently linked; the signed-in user must explicitly link the provider. Managed SSO can additionally require a provider-verified email in the organization's domain.

## Built-in routes

`Auth.Handler()` registers routes under `/api/auth` by default. Set `Config.BasePath` to change the prefix.

| Enabled feature | Routes |
| --- | --- |
| Email/password | `POST /sign-up/email`, `POST /sign-in/email` |
| Social and OIDC SSO | `GET /sign-in/social/{provider}`, `GET /sign-in/sso/{connection}`, `GET or POST /callback/{provider}`, `POST /link/social/{provider}`, `POST /link/sso/{connection}` |
| Two-factor plugin | `POST /two-factor/enroll`, `/two-factor/confirm`, `/two-factor/complete` |
| Passkey plugin | `POST /passkey/register/begin`, `/register/finish`, `/sign-in/begin`, `/sign-in/finish` |
| Organization plugin | `POST /organization/create`, `GET /organization/list` |
| Team store | `GET/POST /organization/{orgId}/teams`, plus team and member detail routes in the [guide](docs/organizations.md) |
| Always | `GET /session`, `POST /sign-out` |

On HTTPS, AuthKit sets HTTP-only, `Secure`, host-bound session and OAuth flow cookies. Cookie-authenticated mutations check request origin; OAuth callbacks use one-time server-side flow state. PostgreSQL stores only session token hashes. See the [operational notes](#before-production) for deployment requirements.

## Before production

- Use an HTTPS `BaseURL`, register exact OAuth callback URLs, and keep provider secrets, the Ed25519 seed, and any managed SSO encryption key persistent and private.
- Add application-level rate limits and email verification for public password sign-up. AuthKit creates an account from the submitted email immediately; email verification and password reset are not built-in routes.
- Run `postgres.NewSessions(pool).PurgeExpired(ctx)` and `postgres.NewFlows(pool).PurgeExpired(ctx)` periodically. Protect database access and backups; the PostgreSQL adapter stores TOTP secrets in plaintext.
- Managed SSO provides the configuration service, not admin or discovery HTTP endpoints. Rebuild the `Auth` instance on every server after a connection is changed, verified, or deleted. SAML and SCIM are outside the current scope.

## Project

AuthKit is MIT licensed. See the [latest release](https://github.com/goat-io/authkit/releases), [Go package reference](https://pkg.go.dev/github.com/goat-io/authkit), [organization and SSO guide](docs/organizations.md), or [open an issue](https://github.com/goat-io/authkit/issues).

For local verification, run `go test ./...`. PostgreSQL integration tests use `AUTHKIT_TEST_DATABASE_URL` when set and skip when their database is unreachable. CI runs them against PostgreSQL with the race detector and compiles the runnable README example.
