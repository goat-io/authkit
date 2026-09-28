package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestSocialAccountsJoinVerifiedEmail(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	accounts := pgstore.NewSocialAccounts(pool)
	person := identity.SocialIdentity{Provider: "google", Subject: "g-1", Email: "a@example.com", EmailVerified: true}
	userID, err := accounts.ResolveOrCreate(ctx, person)
	if err != nil {
		t.Fatal(err)
	}
	user, err := pgstore.NewUsers(pool).GetByID(ctx, userID)
	if err != nil || user.Email != person.Email {
		t.Fatalf("user: %+v, %v", user, err)
	}
	if got, err := accounts.ResolveOrCreate(ctx, person); err != nil || got != userID {
		t.Fatalf("repeat: %s, %v", got, err)
	}
	sessions := identity.NewSessionService(pgstore.NewSessions(pool), pgstore.NewUsers(pool), nil, 0)
	login := identity.NewSocialLoginService(accounts, sessions)
	token, err := login.SignIn(ctx, person)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := sessions.Resolve(ctx, token)
	if !ok || current.Kind != identity.KindUser || current.Subject != userID {
		t.Fatalf("social session: %+v, %v", current, ok)
	}

	other := identity.SocialIdentity{Provider: "linkedin", Subject: "l-1", Email: person.Email, EmailVerified: true}
	if got, err := accounts.ResolveOrCreate(ctx, other); err != nil || got != userID {
		t.Fatalf("verified email should use existing account: %s, %v", got, err)
	}
	unverified := identity.SocialIdentity{Provider: "linkedin", Subject: "l-unverified", Email: person.Email}
	if got, err := accounts.ResolveOrCreate(ctx, unverified); err != nil || got == userID {
		t.Fatalf("unverified email must not claim existing account: %s, %v", got, err)
	}

	third := identity.SocialIdentity{Provider: "apple", Subject: "a-1"}
	thirdID, err := accounts.ResolveOrCreate(ctx, third)
	if err != nil || thirdID == userID {
		t.Fatalf("email-less account: %s, %v", thirdID, err)
	}
	if err := accounts.Link(ctx, thirdID, person); !errors.Is(err, identity.ErrSocialIdentity) {
		t.Fatalf("account takeover: %v", err)
	}
}

func TestSocialAccountsJoinExistingPasswordUser(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	users := pgstore.NewUsers(pool)
	hash, err := identity.HashPassword("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(ctx, identity.User{ID: "existing-user", Email: "Person@Example.com", PasswordHash: hash}); err != nil {
		t.Fatal(err)
	}
	accounts := pgstore.NewSocialAccounts(pool)
	person := identity.SocialIdentity{Provider: "google", Subject: "verified-google-subject", Email: "person@example.com", EmailVerified: true}
	if got, err := accounts.ResolveOrCreate(ctx, person); err != nil || got != "existing-user" {
		t.Fatalf("verified Google email should resolve password user: %s, %v", got, err)
	}
	if got, err := accounts.ResolveOrCreate(ctx, person); err != nil || got != "existing-user" {
		t.Fatalf("repeat Google sign-in: %s, %v", got, err)
	}
	sessions := identity.NewSessionService(pgstore.NewSessions(pool), users, nil, 0)
	password := identity.NewLoginService(sessions, users, nil, nil)
	if result, err := password.Login(ctx, "person@example.com", "correct-password"); err != nil || result.Session == "" {
		t.Fatalf("password sign-in for existing account: %v", err)
	}
	var code string
	emailOTP := identity.NewEmailOTPService(pgstore.NewEmailOTPs(pool), users, sessions, []byte("test-secret"),
		func(_ context.Context, _, sentCode string) error { code = sentCode; return nil })
	if _, err := emailOTP.Start(ctx, "person@example.com"); err != nil {
		t.Fatal(err)
	}
	token, err := emailOTP.Finish(ctx, "person@example.com", code)
	if err != nil {
		t.Fatal(err)
	}
	if principal, ok := sessions.Resolve(ctx, token); !ok || principal.Subject != "existing-user" {
		t.Fatalf("email code opened another account: %+v %v", principal, ok)
	}
	u, err := users.GetByID(ctx, "existing-user")
	if err != nil || !identity.CheckPassword(u.PasswordHash, "correct-password") {
		t.Fatalf("existing password was changed: %v", err)
	}
}

func TestSocialAccountsConcurrentSignIn(t *testing.T) {
	pool := testPool(t)
	accounts := pgstore.NewSocialAccounts(pool)
	person := identity.SocialIdentity{Provider: "apple", Subject: "same-subject", Email: "race@example.com", EmailVerified: true}
	var wg sync.WaitGroup
	ids := make([]string, 8)
	errs := make([]error, 8)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = accounts.ResolveOrCreate(context.Background(), person)
		}(i)
	}
	wg.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] == "" || ids[i] != ids[0] {
			t.Fatalf("race result %d: %s, %v", i, ids[i], errs[i])
		}
	}
}
