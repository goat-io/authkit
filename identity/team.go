package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrTeamForbidden = errors.New("team access denied")
	ErrTeamNotFound  = errors.New("team not found")
	ErrTeamConflict  = errors.New("team conflict")
)

// Team belongs to one organization. Slugs are unique within that organization.
type Team struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"orgId"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"createdAt"`
}

type TeamMembership struct {
	TeamID string `json:"teamId"`
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// TeamStore is the canonical authorization boundary for team membership.
// Mutations take the actor ID so authorization and the write share a transaction.
type TeamStore interface {
	Create(ctx context.Context, actorID string, team Team) error
	ListForUser(ctx context.Context, actorID, orgID string) ([]Team, error)
	Get(ctx context.Context, actorID, orgID, teamID string) (Team, bool, error)
	Members(ctx context.Context, actorID, orgID, teamID string) ([]TeamMembership, error)
	AddMember(ctx context.Context, actorID, orgID, teamID, userID, role string) error
	RemoveMember(ctx context.Context, actorID, orgID, teamID, userID string) error
	Delete(ctx context.Context, actorID, orgID, teamID string) error
}
