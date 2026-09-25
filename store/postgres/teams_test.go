package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestTeamsKeepMembershipInsideOrganization(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	orgs := pgstore.NewOrgs(pool)
	users := pgstore.NewUsers(pool)
	memberships := pgstore.NewMemberships(pool)
	teams := pgstore.NewTeams(pool)
	for _, orgID := range []string{"org-a", "org-b"} {
		if err := orgs.Create(ctx, identity.Org{ID: orgID, Name: orgID, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, userID := range []string{"owner", "member", "outsider"} {
		if err := users.Create(ctx, identity.User{ID: userID, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	if err := memberships.Add(ctx, "owner", "org-a", "owner"); err != nil {
		t.Fatal(err)
	}
	if err := memberships.Add(ctx, "member", "org-a", "member"); err != nil {
		t.Fatal(err)
	}
	if err := memberships.Add(ctx, "outsider", "org-b", "owner"); err != nil {
		t.Fatal(err)
	}
	team := identity.Team{ID: "team-a", OrgID: "org-a", Name: "Engineering", Slug: "engineering", CreatedAt: time.Now()}
	if err := teams.Create(ctx, "member", team); !errors.Is(err, identity.ErrTeamForbidden) {
		t.Fatalf("member created team: %v", err)
	}
	if err := teams.Create(ctx, "owner", team); err != nil {
		t.Fatal(err)
	}
	if err := teams.AddMember(ctx, "owner", "org-a", team.ID, "outsider", "member"); !errors.Is(err, identity.ErrTeamConflict) {
		t.Fatalf("cross-org member accepted: %v", err)
	}
	if err := teams.AddMember(ctx, "owner", "org-a", team.ID, "member", "member"); err != nil {
		t.Fatal(err)
	}
	if got, err := teams.ListForUser(ctx, "outsider", "org-a"); !errors.Is(err, identity.ErrTeamForbidden) || got != nil {
		t.Fatalf("cross-org list: %v, %v", got, err)
	}
	if got, found, err := teams.Get(ctx, "member", "org-a", team.ID); err != nil || !found || got.ID != team.ID {
		t.Fatalf("member cannot see team: %+v %v %v", got, found, err)
	}
	if err := teams.RemoveMember(ctx, "member", "org-a", team.ID, "owner"); !errors.Is(err, identity.ErrTeamForbidden) {
		t.Fatalf("member removed owner: %v", err)
	}
	if err := teams.RemoveMember(ctx, "owner", "org-a", team.ID, "owner"); !errors.Is(err, identity.ErrTeamNotFound) {
		t.Fatalf("team owner removed: %v", err)
	}
	if err := teams.Delete(ctx, "outsider", "org-a", team.ID); !errors.Is(err, identity.ErrTeamForbidden) {
		t.Fatalf("cross-org delete: %v", err)
	}
}
