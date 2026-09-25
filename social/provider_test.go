package social

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func TestCodeFlowVerifiesStateNonceAndToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var nonce string
	var lastIDToken string
	audience := "client"
	requireVerifier := true
	tokenEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.FormValue("code") != "valid-code" || (requireVerifier && r.FormValue("code_verifier") == "") {
			http.Error(w, "bad exchange", http.StatusBadRequest)
			return
		}
		claims := jwt.MapClaims{"iss": "https://issuer.example", "aud": audience, "sub": "person-1",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": nonce,
			"email": "p@example.com", "email_verified": true}
		idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		lastIDToken = idToken
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": idToken})
	}))
	defer tokenEndpoint.Close()
	p := &Provider{config: Config{Provider: Google}, oauth: oauth2.Config{
		ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example/callback",
		Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: tokenEndpoint.URL},
	}, verifier: oidc.NewVerifier("https://issuer.example", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: "client"})}
	redirect, pending, err := p.Begin()
	if err != nil {
		t.Fatal(err)
	}
	nonce = pending.Nonce
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != pending.State || u.Query().Get("nonce") != pending.Nonce || u.Query().Get("code_challenge") == "" {
		t.Fatalf("missing flow protections: %s", redirect)
	}
	if _, err := p.Complete(context.Background(), pending, "wrong", "valid-code"); err != ErrInvalidCallback {
		t.Fatalf("state: %v", err)
	}
	person, err := p.Complete(context.Background(), pending, pending.State, "valid-code")
	if err != nil {
		t.Fatal(err)
	}
	if person.Provider != Google || person.Subject != "person-1" || person.Email != "p@example.com" || !person.EmailVerified {
		t.Fatalf("bad identity: %+v", person)
	}
	nonce = "wrong-nonce"
	if _, err := p.Complete(context.Background(), pending, pending.State, "valid-code"); err != ErrInvalidCallback {
		t.Fatalf("nonce: %v", err)
	}
	nonce = pending.Nonce
	audience = "another-client"
	if _, err := p.Complete(context.Background(), pending, pending.State, "valid-code"); err == nil {
		t.Fatal("wrong audience accepted")
	}
	audience = "client"
	pending.CreatedAt = time.Now().Add(-11 * time.Minute)
	if _, err := p.Complete(context.Background(), pending, pending.State, "valid-code"); err != ErrInvalidCallback {
		t.Fatalf("expired state: %v", err)
	}
	if !strings.Contains(redirect, "code_challenge_method=S256") {
		t.Fatal("PKCE must use S256")
	}
	p.config.Provider = LinkedIn
	requireVerifier = false
	nonce = ""
	redirect, pending, err = p.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(redirect, "nonce=") {
		t.Fatal("LinkedIn flow requested unsupported nonce")
	}
	if _, err := p.Complete(context.Background(), pending, pending.State, "valid-code"); err != nil {
		t.Fatalf("LinkedIn callback: %v", err)
	}
	if _, err := p.VerifyIDToken(context.Background(), "token", "nonce"); err != ErrInvalidCallback {
		t.Fatalf("direct LinkedIn token: %v", err)
	}
	p.config.Provider = Google
	p.nativeVerifiers = []*oidc.IDTokenVerifier{p.verifier, oidc.NewVerifier("https://issuer.example", &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, &oidc.Config{ClientID: "native-client"})}
	audience = "native-client"
	nonce = pending.Nonce
	if _, err := p.Complete(context.Background(), pending, pending.State, "valid-code"); err == nil {
		t.Fatal("web callback accepted native audience")
	}
	if _, err := p.VerifyIDToken(context.Background(), lastIDToken, nonce); err != nil {
		t.Fatalf("native audience: %v", err)
	}
}

func TestCustomOIDCIsolatesOrganizationAccounts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	makeProvider := func(org string) *Provider {
		p, err := New(ctx, Config{Provider: "acme", IssuerURL: issuer, AccountNamespace: org, ClientID: "client", ClientSecret: "secret", RedirectURL: "https://app.example/callback/acme"})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	first, second := makeProvider("org_1"), makeProvider("org_2")
	claims := jwt.MapClaims{"iss": issuer, "aud": "client", "sub": "person-1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": "once"}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := first.VerifyIDToken(ctx, raw, "once")
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.VerifyIDToken(ctx, raw, "once")
	if err != nil {
		t.Fatal(err)
	}
	if a.Provider == b.Provider || a.Provider == "acme" || a.Subject != b.Subject {
		t.Fatalf("account namespace was not isolated: %+v %+v", a, b)
	}
	if _, err := first.VerifyIDToken(ctx, raw, "wrong"); err == nil {
		t.Fatal("wrong nonce accepted")
	}
}

func TestAppleClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{config: Config{Provider: Apple, ClientID: "com.example.app", AppleTeamID: "TEAM123", AppleKeyID: "KEY123", ApplePrivateKey: key}}
	secret, err := p.appleClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseWithClaims(secret, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != "ES256" || token.Header["kid"] != "KEY123" {
			t.Fatal("wrong Apple signing header")
		}
		return &key.PublicKey, nil
	}, jwt.WithIssuer("TEAM123"), jwt.WithAudience("https://appleid.apple.com"))
	if err != nil || !parsed.Valid || parsed.Claims.(*jwt.RegisteredClaims).Subject != "com.example.app" {
		t.Fatalf("invalid Apple secret: %v", err)
	}
}

type rewriteTransport struct{ target *url.URL }

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.URL.Scheme, clone.URL.Host = t.target.Scheme, t.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func TestGitHubUsesStableIDAndVerifiedEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access" {
			t.Error("missing access token")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"id":42,"login":"octocat"}`))
		case "/user/emails":
			_, _ = w.Write([]byte(`[{"email":"unverified@example.com","primary":true,"verified":false},{"email":"verified@example.com","primary":true,"verified":true}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: rewriteTransport{target: target}})
	p := &Provider{oauth: oauth2.Config{}}
	person, err := p.githubIdentity(ctx, &oauth2.Token{AccessToken: "access", TokenType: "Bearer"})
	if err != nil {
		t.Fatal(err)
	}
	if person.Provider != GitHub || person.Subject != "42" || person.Email != "verified@example.com" || !person.EmailVerified || person.DisplayName != "octocat" {
		t.Fatalf("bad GitHub identity: %+v", person)
	}
}
