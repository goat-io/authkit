package authkit

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/goat-io/authkit/identity"
)

var teamSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func teamSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func teamActor(a *Auth, w http.ResponseWriter, r *http.Request) (string, bool) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return "", false
	}
	return p.Subject, true
}

func teamHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrTeamForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, identity.ErrTeamNotFound):
		http.Error(w, "team not found", http.StatusNotFound)
	case errors.Is(err, identity.ErrTeamConflict):
		http.Error(w, "team conflict", http.StatusConflict)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (a *Auth) createTeam(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Slug == "" {
		body.Slug = teamSlug(body.Name)
	}
	body.Slug = strings.ToLower(strings.TrimSpace(body.Slug))
	if body.Name == "" || len(body.Name) > 200 || !teamSlugPattern.MatchString(body.Slug) {
		http.Error(w, "invalid team name or slug", http.StatusBadRequest)
		return
	}
	id, err := randomID("team_")
	if err != nil {
		teamHTTPError(w, err)
		return
	}
	team := identity.Team{ID: id, OrgID: r.PathValue("orgId"), Name: body.Name, Slug: body.Slug, CreatedAt: time.Now().UTC()}
	if err := a.config.Storage.Teams.Create(r.Context(), actor, team); err != nil {
		teamHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"team": team})
}

func (a *Auth) listTeams(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	teams, err := a.config.Storage.Teams.ListForUser(r.Context(), actor, r.PathValue("orgId"))
	if err != nil {
		teamHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"teams": teams})
}

func (a *Auth) getTeam(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	team, found, err := a.config.Storage.Teams.Get(r.Context(), actor, r.PathValue("orgId"), r.PathValue("teamId"))
	if err != nil {
		teamHTTPError(w, err)
		return
	}
	if !found {
		teamHTTPError(w, identity.ErrTeamNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"team": team})
}

func (a *Auth) deleteTeam(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	if err := a.config.Storage.Teams.Delete(r.Context(), actor, r.PathValue("orgId"), r.PathValue("teamId")); err != nil {
		teamHTTPError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) listTeamMembers(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	members, err := a.config.Storage.Teams.Members(r.Context(), actor, r.PathValue("orgId"), r.PathValue("teamId"))
	if err != nil {
		teamHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}

func (a *Auth) putTeamMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Role != "member" && body.Role != "admin" {
		http.Error(w, "invalid team role", http.StatusBadRequest)
		return
	}
	if err := a.config.Storage.Teams.AddMember(r.Context(), actor, r.PathValue("orgId"), r.PathValue("teamId"), r.PathValue("userId"), body.Role); err != nil {
		teamHTTPError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) deleteTeamMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := teamActor(a, w, r)
	if !ok {
		return
	}
	if err := a.config.Storage.Teams.RemoveMember(r.Context(), actor, r.PathValue("orgId"), r.PathValue("teamId"), r.PathValue("userId")); err != nil {
		teamHTTPError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
