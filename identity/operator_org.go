package identity

import (
	"context"
	"errors"
)

var (
	ErrOperatorPermission  = errors.New("operator organization requires operator access")
	ErrOperatorOrgNotFound = errors.New("operator organization not found")
)

// OperatorOrgStore atomically designates one organization as the operator.
// A storage adapter must leave the current designation unchanged if orgID
// does not exist.
type OperatorOrgStore interface {
	SetOperator(ctx context.Context, orgID string) (bool, error)
}

// OperatorOrgService checks the authenticated principal before changing the
// designated organization. A bootstrap admin credential can make the first
// designation; afterwards, members of the operator organization can transfer
// it using their own sessions.
type OperatorOrgService struct{ store OperatorOrgStore }

func NewOperatorOrgService(store OperatorOrgStore) *OperatorOrgService {
	return &OperatorOrgService{store: store}
}

func (s *OperatorOrgService) Set(ctx context.Context, actor Principal, orgID string) error {
	if !actor.IsAdmin() {
		return ErrOperatorPermission
	}
	if orgID == "" {
		return ErrOperatorOrgNotFound
	}
	ok, err := s.store.SetOperator(ctx, orgID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOperatorOrgNotFound
	}
	return nil
}
