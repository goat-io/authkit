package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestPersonalOrganizationIsUniqueAndOwned(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgs := pgstore.NewOrgs(pool)
	users := pgstore.NewUsers(pool)
	if err := users.Create(ctx, identity.User{ID: "person", Email: "person@example.test", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := orgs.Create(ctx, identity.Org{ID: "company", Name: "Company", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := pgstore.NewMemberships(pool).Add(ctx, "person", "company", "member"); err != nil {
		t.Fatal(err)
	}
	personal := identity.Org{ID: "home", Name: "Person", CreatedAt: time.Now().UTC()}
	if err := orgs.CreatePersonalForUser(ctx, personal, "person"); err != nil {
		t.Fatal(err)
	}
	got, found, err := orgs.GetByID(ctx, "home")
	if err != nil || !found || got.PersonalOwnerID != "person" {
		t.Fatalf("personal owner not persisted: %+v %v %v", got, found, err)
	}
	if err := orgs.CreatePersonalForUser(ctx, identity.Org{ID: "home-2", Name: "Duplicate", CreatedAt: time.Now().UTC()}, "person"); !errors.Is(err, identity.ErrPersonalOrgExists) {
		t.Fatalf("duplicate personal org: %v", err)
	}
	if _, found, err := orgs.GetByID(ctx, "home-2"); err != nil || found {
		t.Fatalf("duplicate personal org persisted: %v %v", found, err)
	}
}

func TestEnsurePersonalOrganizationIsIdempotent(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	users := pgstore.NewUsers(pool)
	if err := users.Create(ctx, identity.User{ID: "person", Email: "person@example.test", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	orgs := pgstore.NewOrgs(pool)
	first, err := orgs.EnsurePersonalForUser(ctx, "person")
	if err != nil || first.PersonalOwnerID != "person" {
		t.Fatalf("first personal organization: %+v %v", first, err)
	}
	second, err := orgs.EnsurePersonalForUser(ctx, "person")
	if err != nil || second.ID != first.ID {
		t.Fatalf("second personal organization: %+v %v", second, err)
	}
	memberships, err := pgstore.NewMemberships(pool).MembershipsOf(ctx, "person")
	if err != nil || len(memberships) != 1 || memberships[0].OrgID != first.ID || memberships[0].Role != "owner" {
		t.Fatalf("personal membership: %+v %v", memberships, err)
	}
}
