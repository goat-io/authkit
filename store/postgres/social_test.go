package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestSocialAccountsDoNotLinkByEmail(t *testing.T) {
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
	if _, err := accounts.ResolveOrCreate(ctx, other); !errors.Is(err, identity.ErrEmailInUse) {
		t.Fatalf("expected email conflict, got %v", err)
	}
	if err := login.Link(ctx, current, other); err != nil {
		t.Fatal(err)
	}
	if got, err := accounts.ResolveOrCreate(ctx, other); err != nil || got != userID {
		t.Fatalf("linked account: %s, %v", got, err)
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
