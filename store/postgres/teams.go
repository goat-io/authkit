package postgres

import (
	"context"
	"errors"

	"github.com/goat-io/authkit/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Teams struct{ pool *pgxpool.Pool }

func NewTeams(pool *pgxpool.Pool) *Teams { return &Teams{pool: pool} }

var _ identity.TeamStore = (*Teams)(nil)

func teamConflict(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23505" || pgErr.Code == "23503") {
		return identity.ErrTeamConflict
	}
	return err
}

// orgRole is queried inside mutations so a revoked organization role cannot
// authorize a later write from a stale browser session.
func orgRole(ctx context.Context, tx pgx.Tx, actorID, orgID string) (string, error) {
	var role string
	err := tx.QueryRow(ctx, `SELECT role FROM authkit_memberships WHERE user_id=$1 AND org_id=$2 FOR SHARE`, actorID, orgID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", identity.ErrTeamForbidden
	}
	return role, err
}

func teamRole(ctx context.Context, tx pgx.Tx, actorID, orgID, teamID string) (string, error) {
	var role string
	err := tx.QueryRow(ctx, `SELECT tm.role FROM authkit_team_memberships tm JOIN authkit_teams t ON t.id=tm.team_id WHERE t.id=$1 AND t.org_id=$2 AND tm.user_id=$3 FOR SHARE OF tm`, teamID, orgID, actorID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", identity.ErrTeamForbidden
	}
	return role, err
}

func (s *Teams) Create(ctx context.Context, actorID string, team identity.Team) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	role, err := orgRole(ctx, tx, actorID, team.OrgID)
	if err != nil {
		return err
	}
	if role != "owner" && role != "admin" {
		return identity.ErrTeamForbidden
	}
	if _, err = tx.Exec(ctx, `INSERT INTO authkit_teams(id,org_id,name,slug,created_at) VALUES ($1,$2,$3,$4,$5)`, team.ID, team.OrgID, team.Name, team.Slug, team.CreatedAt); err != nil {
		return teamConflict(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO authkit_team_memberships(team_id,user_id,role) VALUES ($1,$2,'owner')`, team.ID, actorID); err != nil {
		return teamConflict(err)
	}
	return tx.Commit(ctx)
}

func (s *Teams) ListForUser(ctx context.Context, actorID, orgID string) ([]identity.Team, error) {
	var role string
	err := s.pool.QueryRow(ctx, `SELECT role FROM authkit_memberships WHERE user_id=$1 AND org_id=$2`, actorID, orgID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, identity.ErrTeamForbidden
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT t.id,t.org_id,t.name,t.slug,t.created_at FROM authkit_teams t WHERE t.org_id=$1 AND ($3 OR EXISTS (SELECT 1 FROM authkit_team_memberships tm WHERE tm.team_id=t.id AND tm.user_id=$2)) ORDER BY t.created_at,t.id`, orgID, actorID, role == "owner" || role == "admin")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identity.Team{}
	for rows.Next() {
		var t identity.Team
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.Slug, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Teams) Get(ctx context.Context, actorID, orgID, teamID string) (identity.Team, bool, error) {
	teams, err := s.ListForUser(ctx, actorID, orgID)
	if err != nil {
		return identity.Team{}, false, err
	}
	for _, t := range teams {
		if t.ID == teamID {
			return t, true, nil
		}
	}
	return identity.Team{}, false, nil
}

func (s *Teams) Members(ctx context.Context, actorID, orgID, teamID string) ([]identity.TeamMembership, error) {
	if _, found, err := s.Get(ctx, actorID, orgID, teamID); err != nil {
		return nil, err
	} else if !found {
		return nil, identity.ErrTeamNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT team_id,user_id,role FROM authkit_team_memberships WHERE team_id=$1 ORDER BY user_id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identity.TeamMembership{}
	for rows.Next() {
		var m identity.TeamMembership
		if err := rows.Scan(&m.TeamID, &m.UserID, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Teams) AddMember(ctx context.Context, actorID, orgID, teamID, userID, role string) error {
	if role != "admin" && role != "member" {
		return identity.ErrTeamConflict
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	org, err := orgRole(ctx, tx, actorID, orgID)
	if err != nil {
		return err
	}
	if org != "owner" && org != "admin" {
		team, err := teamRole(ctx, tx, actorID, orgID, teamID)
		if err != nil {
			return err
		}
		if team != "owner" && team != "admin" {
			return identity.ErrTeamForbidden
		}
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM authkit_teams WHERE id=$1 AND org_id=$2)`, teamID, orgID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return identity.ErrTeamNotFound
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM authkit_memberships WHERE user_id=$1 AND org_id=$2)`, userID, orgID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return identity.ErrTeamConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO authkit_team_memberships(team_id,user_id,role) VALUES ($1,$2,$3) ON CONFLICT(team_id,user_id) DO UPDATE SET role=EXCLUDED.role WHERE authkit_team_memberships.role <> 'owner'`, teamID, userID, role)
	if err != nil {
		return teamConflict(err)
	}
	return tx.Commit(ctx)
}

func (s *Teams) RemoveMember(ctx context.Context, actorID, orgID, teamID, userID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	org, err := orgRole(ctx, tx, actorID, orgID)
	if err != nil {
		return err
	}
	if org != "owner" && org != "admin" {
		team, err := teamRole(ctx, tx, actorID, orgID, teamID)
		if err != nil {
			return err
		}
		if team != "owner" && team != "admin" {
			return identity.ErrTeamForbidden
		}
	}
	result, err := tx.Exec(ctx, `DELETE FROM authkit_team_memberships tm USING authkit_teams t WHERE t.id=tm.team_id AND t.id=$1 AND t.org_id=$2 AND tm.user_id=$3 AND tm.role <> 'owner'`, teamID, orgID, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return identity.ErrTeamNotFound
	}
	return tx.Commit(ctx)
}

func (s *Teams) Delete(ctx context.Context, actorID, orgID, teamID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	org, err := orgRole(ctx, tx, actorID, orgID)
	if err != nil {
		return err
	}
	if org != "owner" && org != "admin" {
		team, err := teamRole(ctx, tx, actorID, orgID, teamID)
		if err != nil {
			return err
		}
		if team != "owner" {
			return identity.ErrTeamForbidden
		}
	}
	result, err := tx.Exec(ctx, `DELETE FROM authkit_teams WHERE id=$1 AND org_id=$2`, teamID, orgID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return identity.ErrTeamNotFound
	}
	return tx.Commit(ctx)
}
