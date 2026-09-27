package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestEmailOTPSignIn(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	users := pgstore.NewUsers(pool)
	sessions := identity.NewSessionService(pgstore.NewSessions(pool), users, pgstore.NewMemberships(pool), 0)
	var code string
	service := identity.NewEmailOTPService(pgstore.NewEmailOTPs(pool), users, sessions, []byte("test-secret"),
		func(_ context.Context, _, sentCode string) error { code = sentCode; return nil })
	if _, err := service.Start(ctx, " PERSON@Example.test "); err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("code length = %d", len(code))
	}
	if _, err := service.Start(ctx, "person@example.test"); !errors.Is(err, identity.ErrEmailOTPCooldown) {
		t.Fatalf("cooldown: %v", err)
	}
	if _, err := service.Finish(ctx, "person@example.test", "000000"); !errors.Is(err, identity.ErrEmailOTPInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	token, err := service.Finish(ctx, "person@example.test", code)
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := sessions.Resolve(ctx, token)
	if !ok || principal.Subject == "" {
		t.Fatalf("email session invalid: %+v %v", principal, ok)
	}
	user, err := users.GetByEmail(ctx, "person@example.test")
	if err != nil || user.ID != principal.Subject {
		t.Fatalf("email user: %+v %v", user, err)
	}
	if _, err := service.Finish(ctx, "person@example.test", code); !errors.Is(err, identity.ErrEmailOTPInvalid) {
		t.Fatalf("reused code: %v", err)
	}
}

func TestEmailOTPFailedDeliveryAllowsRetry(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	users := pgstore.NewUsers(pool)
	sessions := identity.NewSessionService(pgstore.NewSessions(pool), users, nil, 0)
	store := pgstore.NewEmailOTPs(pool)
	failed := identity.NewEmailOTPService(store, users, sessions, []byte("test-secret"),
		func(context.Context, string, string) error { return errors.New("mail unavailable") })
	if _, err := failed.Start(ctx, "retry@example.test"); err == nil {
		t.Fatal("missing delivery error")
	}
	working := identity.NewEmailOTPService(store, users, sessions, []byte("test-secret"),
		func(context.Context, string, string) error { return nil })
	if _, err := working.Start(ctx, "retry@example.test"); err != nil {
		t.Fatalf("retry after failed delivery: %v", err)
	}
}
