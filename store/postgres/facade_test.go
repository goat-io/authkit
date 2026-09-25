package postgres_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goat-io/authkit"
	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
	"github.com/goat-io/authkit/token/eddsa"
	"github.com/goat-io/authkit/webauthn/gowebauthn"
)

func TestOneConfigWiresRoutesAndPlugins(t *testing.T) {
	pool := testPool(t)
	signer, _, err := eddsa.Generate()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authkit.New(context.Background(), authkit.Config{
		BaseURL: "http://localhost:8080",
		Storage: authkit.Postgres(pool), Signer: signer,
		EmailAndPassword: authkit.EmailAndPassword{Enabled: true},
		SocialProviders:  map[string]authkit.SocialProvider{"github": {ClientID: "client", ClientSecret: "secret"}},
		Plugins: []authkit.Plugin{
			authkit.TwoFactor(),
			authkit.Passkey(gowebauthn.Config{RPID: "localhost", RPDisplayName: "Test", RPOrigins: []string{"http://localhost:8080"}}),
			authkit.Organization(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.Handler()
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	signup := request(http.MethodPost, "/api/auth/sign-up/email", `{"email":"new@example.com","password":"password123"}`, nil)
	if signup.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", signup.Code, signup.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range signup.Result().Cookies() {
		if cookie.Name == "authkit.session" {
			session = cookie
		}
	}
	if session == nil {
		t.Fatal("session cookie missing")
	}
	if got := request(http.MethodPost, "/api/auth/organization/create", `{"name":"My team"}`, session); got.Code != http.StatusCreated {
		t.Fatalf("organization: %d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/auth/passkey/register/begin", "", session); got.Code != http.StatusOK {
		t.Fatalf("passkey: %d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/auth/two-factor/enroll", "", session); got.Code != http.StatusOK {
		t.Fatalf("two-factor: %d %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodGet, "/api/auth/sign-in/social/github", "", nil); got.Code != http.StatusFound {
		t.Fatalf("GitHub redirect: %d %s", got.Code, got.Body.String())
	}
}

func TestSSOMembershipPreservesExistingRole(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := pgstore.NewUsers(pool).Create(ctx, identity.User{ID: "user", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := pgstore.NewOrgs(pool).Create(ctx, identity.Org{ID: "org", Name: "Test", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	memberships := pgstore.NewMemberships(pool)
	if err := memberships.EnsureMembership(ctx, "user", "org", "member"); err != nil {
		t.Fatal(err)
	}
	if err := memberships.Add(ctx, "user", "org", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := memberships.EnsureMembership(ctx, "user", "org", "member"); err != nil {
		t.Fatal(err)
	}
	got, err := memberships.MembershipsOf(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Role != "owner" {
		t.Fatalf("SSO changed an existing role: %+v", got)
	}
}
