package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestOperatorOrganizationGrantsEveryMemberAdminAccess(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgs := pgstore.NewOrgs(pool)
	users := pgstore.NewUsers(pool)
	memberships := pgstore.NewMemberships(pool)
	sessions := identity.NewSessionService(pgstore.NewSessions(pool), users, memberships, 0)
	for _, id := range []string{"org_one", "org_two"} {
		if err := orgs.Create(ctx, identity.Org{ID: id, Name: id, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := users.Create(ctx, identity.User{ID: "member", Email: "member@example.test", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := memberships.Add(ctx, "member", "org_one", "member"); err != nil {
		t.Fatal(err)
	}
	token, err := sessions.Issue(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	actor, ok := sessions.Resolve(ctx, token)
	if !ok || actor.IsAdmin() {
		t.Fatalf("ordinary member unexpectedly admin: %+v", actor)
	}
	operator := identity.NewOperatorOrgService(orgs)
	if err := operator.Set(ctx, actor, "org_one"); !errors.Is(err, identity.ErrOperatorPermission) {
		t.Fatalf("member designated operator: %v", err)
	}
	if err := operator.Set(ctx, identity.Principal{Kind: identity.KindAdmin}, "missing"); !errors.Is(err, identity.ErrOperatorOrgNotFound) {
		t.Fatalf("missing org: %v", err)
	}
	if err := operator.Set(ctx, identity.Principal{Kind: identity.KindAdmin}, "org_one"); err != nil {
		t.Fatal(err)
	}
	actor, ok = sessions.Resolve(ctx, token)
	if !ok || !actor.IsAdmin() || !actor.Operator || actor.OrgID != "org_one" {
		t.Fatalf("operator membership not reflected in existing session: %+v", actor)
	}
	if err := operator.Set(ctx, actor, "org_two"); err != nil {
		t.Fatal(err)
	}
	actor, _ = sessions.Resolve(ctx, token)
	if actor.IsAdmin() {
		t.Fatalf("old org retained operator rights: %+v", actor)
	}
	one, _, err := orgs.GetByID(ctx, "org_one")
	if err != nil || one.Operator {
		t.Fatalf("old org operator flag: %+v %v", one, err)
	}
	two, _, err := orgs.GetByID(ctx, "org_two")
	if err != nil || !two.Operator {
		t.Fatalf("new org operator flag: %+v %v", two, err)
	}
}
