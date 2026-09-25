// Package eddsa is authkit's default Signer adapter: short-lived EdDSA (Ed25519)
// JWTs verified by signature only, with a published JWKS. Stateless verification
// keeps services horizontally scalable.
package eddsa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultIssuer   = "authkit"
	defaultAudience = "authkit"
)

type claims struct {
	jwt.RegisteredClaims
	OrgID  string   `json:"org,omitempty"`
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// Signer mints/verifies JWTs with one Ed25519 keypair.
type Signer struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	kid      string
	issuer   string
	audience string
}

// New builds a Signer from a 32-byte Ed25519 seed (share the same seed across all
// pods so any can verify what another minted).
func New(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &Signer{priv: priv, pub: pub, kid: hex.EncodeToString(sum[:])[:16], issuer: defaultIssuer, audience: defaultAudience}, nil
}

// Generate returns a Signer with a fresh random key and its seed (persist the
// seed to reuse the key across restarts/pods).
func Generate() (*Signer, []byte, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	seed := priv.Seed()
	s, err := New(seed)
	return s, seed, err
}

func (s *Signer) WithIssuerAudience(issuer, audience string) *Signer {
	s.issuer, s.audience = issuer, audience
	return s
}

// Mint implements identity.Signer.
func (s *Signer) Mint(c identity.Claims, ttl time.Duration) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)
	cl := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   c.Subject,
			Audience:  jwt.ClaimStrings{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		OrgID:  c.OrgID,
		Roles:  c.Roles,
		Scopes: c.Scopes,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, cl)
	tok.Header["kid"] = s.kid
	signed, err := tok.SignedString(s.priv)
	return signed, exp, err
}

// Verify implements identity.Signer.
func (s *Signer) Verify(token string) (identity.Claims, error) {
	cl := &claims{}
	_, err := jwt.ParseWithClaims(token, cl, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		return s.pub, nil
	}, jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience), jwt.WithValidMethods([]string{"EdDSA"}))
	if err != nil {
		return identity.Claims{}, err
	}
	out := identity.Claims{Subject: cl.Subject, OrgID: cl.OrgID, Roles: cl.Roles, Scopes: cl.Scopes}
	if cl.ExpiresAt != nil {
		out.ExpiresAt = cl.ExpiresAt.Time
	}
	return out, nil
}

// JWKS implements identity.Signer (OKP/Ed25519 public key document).
func (s *Signer) JWKS() map[string]any {
	return map[string]any{
		"keys": []map[string]any{{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": s.kid, "x": base64.RawURLEncoding.EncodeToString(s.pub),
		}},
	}
}
