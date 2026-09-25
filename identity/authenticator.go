package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashSecret hashes an opaque high-entropy secret/token for storage/lookup
// (SHA-256; the secret is random, so a slow KDF buys nothing). Passwords use
// bcrypt instead — see HashPassword.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Authenticator resolves a presented token to a Principal across all three paths:
//   - the shared admin token (operator/bootstrap) — constant-time compare
//   - a machine JWT — verified by signature only (STATELESS, no DB lookup)
//   - a user session — looked up via the optional SessionService (stateful, the
//     right trade for human sessions: instant revocation)
//
// Order matters: the stateless JWT check runs before the session lookup, so
// machine traffic never touches the session store.
type Authenticator struct {
	adminToken string
	signer     Signer
	sessions   *SessionService
}

func NewAuthenticator(adminToken string, signer Signer) *Authenticator {
	return &Authenticator{adminToken: adminToken, signer: signer}
}

// WithSessions enables the user-session path. Returns the receiver for chaining.
func (a *Authenticator) WithSessions(s *SessionService) *Authenticator {
	a.sessions = s
	return a
}

// Authenticate returns the Principal for a token, or KindAnonymous if empty/
// unknown/invalid/expired (callers reject anonymous).
func (a *Authenticator) Authenticate(ctx context.Context, token string) Principal {
	if token == "" {
		return Principal{Kind: KindAnonymous}
	}
	if a.adminToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(a.adminToken)) == 1 {
		return Principal{Kind: KindAdmin}
	}
	if a.signer != nil {
		if claims, err := a.signer.Verify(token); err == nil {
			if scopeContains(claims.Scopes, MFAChallengeScope) {
				return Principal{Kind: KindAnonymous}
			}
			return Principal{Kind: KindMachine, Subject: claims.Subject, OrgID: claims.OrgID, Roles: claims.Roles, Scopes: claims.Scopes}
		}
	}
	if a.sessions != nil {
		if p, ok := a.sessions.Resolve(ctx, token); ok {
			return p
		}
	}
	return Principal{Kind: KindAnonymous}
}
