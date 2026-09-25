package identity

import (
	"context"
	"time"
)

// org.go — the Organization, the tenancy boundary a User belongs to via a
// Membership (ports.go). Orgs own resources; a user may be a member of several.

// Org is a tenant/organization.
type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

// OrgStore persists organizations. The Postgres adapter is in store/postgres.
type OrgStore interface {
	Create(ctx context.Context, o Org) error
	GetByID(ctx context.Context, id string) (Org, bool, error)
	List(ctx context.Context) ([]Org, error)
}
