package authkit

import (
	"net/http"
	"strings"
	"time"

	"github.com/goat-io/authkit/identity"
)

func (a *Auth) createOrganization(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 200 {
		http.Error(w, "invalid organization name", http.StatusBadRequest)
		return
	}
	id, err := randomID("org_")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	org := identity.Org{ID: id, Name: body.Name, CreatedAt: time.Now().UTC()}
	if err := a.orgCreator.CreateForUser(r.Context(), org, p.Subject); err != nil {
		http.Error(w, "unable to create organization", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"organization": org})
}

func (a *Auth) listOrganizations(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	memberships, err := a.config.Storage.Memberships.MembershipsOf(r.Context(), p.Subject)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	result := make([]identity.Org, 0, len(memberships))
	for _, membership := range memberships {
		org, found, err := a.Organizations.GetByID(r.Context(), membership.OrgID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if found {
			result = append(result, org)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"organizations": result})
}
