package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/goat-io/authkit/social"
)

const sessionCookie = "authkit.session"

type principalKey struct{}

// Middleware resolves authkit's session cookie or a Bearer token and adds the
// principal to the request context. Authorization remains the handler's job.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			token = strings.TrimPrefix(h, "Bearer ")
		} else if c, err := r.Cookie(sessionCookie); err == nil {
			token = c.Value
		}
		p := a.Authenticator.Authenticate(r.Context(), token)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func PrincipalFrom(ctx context.Context) (identity.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(identity.Principal)
	return p, ok
}

// Handler returns ready-to-mount net/http routes under Config.BasePath.
func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()
	prefix := a.basePath
	if a.Password != nil {
		mux.HandleFunc("POST "+prefix+"/sign-up/email", a.signUpEmail)
		mux.HandleFunc("POST "+prefix+"/sign-in/email", a.signInEmail)
	}
	if a.Social != nil {
		mux.HandleFunc("GET "+prefix+"/sign-in/social/{provider}", a.startSocial)
		mux.HandleFunc("POST "+prefix+"/link/social/{provider}", a.startLinkSocial)
		mux.HandleFunc("GET "+prefix+"/sign-in/sso/{provider}", a.startSSO)
		mux.HandleFunc("POST "+prefix+"/link/sso/{provider}", a.startLinkSSO)
		mux.HandleFunc("GET "+prefix+"/callback/{provider}", a.finishSocial)
		mux.HandleFunc("POST "+prefix+"/callback/{provider}", a.finishSocial)
	}
	if a.TwoFactor != nil {
		mux.HandleFunc("POST "+prefix+"/two-factor/complete", a.completeTwoFactor)
		mux.HandleFunc("POST "+prefix+"/two-factor/enroll", a.enrollTwoFactor)
		mux.HandleFunc("POST "+prefix+"/two-factor/confirm", a.confirmTwoFactor)
	}
	if a.Passkeys != nil {
		mux.HandleFunc("POST "+prefix+"/passkey/register/begin", a.beginPasskeyRegistration)
		mux.HandleFunc("POST "+prefix+"/passkey/register/finish", a.finishPasskeyRegistration)
		mux.HandleFunc("POST "+prefix+"/passkey/sign-in/begin", a.beginPasskeySignIn)
		mux.HandleFunc("POST "+prefix+"/passkey/sign-in/finish", a.finishPasskeySignIn)
	}
	if a.Organizations != nil {
		mux.HandleFunc("POST "+prefix+"/organization/create", a.createOrganization)
		mux.HandleFunc("GET "+prefix+"/organization/list", a.listOrganizations)
	}
	if a.config.Storage.Teams != nil {
		mux.HandleFunc("GET "+prefix+"/organization/{orgId}/teams", a.listTeams)
		mux.HandleFunc("POST "+prefix+"/organization/{orgId}/teams", a.createTeam)
		mux.HandleFunc("GET "+prefix+"/organization/{orgId}/teams/{teamId}", a.getTeam)
		mux.HandleFunc("DELETE "+prefix+"/organization/{orgId}/teams/{teamId}", a.deleteTeam)
		mux.HandleFunc("GET "+prefix+"/organization/{orgId}/teams/{teamId}/members", a.listTeamMembers)
		mux.HandleFunc("PUT "+prefix+"/organization/{orgId}/teams/{teamId}/members/{userId}", a.putTeamMember)
		mux.HandleFunc("DELETE "+prefix+"/organization/{orgId}/teams/{teamId}/members/{userId}", a.deleteTeamMember)
	}
	mux.HandleFunc("GET "+prefix+"/session", a.currentSession)
	mux.HandleFunc("POST "+prefix+"/sign-out", a.signOut)
	return mux
}

func (a *Auth) signUpEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Email = strings.ToLower(strings.TrimSpace(body.Email))
	parsed, err := mail.ParseAddress(body.Email)
	if err != nil || parsed.Address != body.Email || len(body.Password) < 8 || len(body.Email) > 320 {
		http.Error(w, "invalid email or password", http.StatusBadRequest)
		return
	}
	hash, err := identity.HashPassword(body.Password)
	if err != nil {
		http.Error(w, "invalid password", http.StatusBadRequest)
		return
	}
	id, err := randomID("usr_")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user := identity.User{ID: id, Email: body.Email, DisplayName: body.Name, PasswordHash: hash, CreatedAt: time.Now().UTC()}
	if err := a.config.Storage.Users.Create(r.Context(), user); err != nil {
		// Store implementations can use their own error mapping. Avoid leaking SQL.
		http.Error(w, "unable to create user", http.StatusConflict)
		return
	}
	token, err := a.Sessions.Issue(r.Context(), id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setSession(w, token)
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (a *Auth) signInEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	result, err := a.Password.Login(r.Context(), strings.ToLower(strings.TrimSpace(body.Email)), body.Password)
	if err != nil {
		http.Error(w, "invalid email or password", http.StatusUnauthorized)
		return
	}
	if result.MFARequired {
		a.setMFAChallenge(w, result.Challenge)
		writeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "challenge": result.Challenge})
		return
	}
	a.setSession(w, result.Session)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) startSocial(w http.ResponseWriter, r *http.Request) {
	if a.ssoOrganizations[r.PathValue("provider")] != "" {
		http.NotFound(w, r)
		return
	}
	a.beginSocial(w, r, "")
}

func (a *Auth) startSSO(w http.ResponseWriter, r *http.Request) {
	if a.ssoOrganizations[r.PathValue("provider")] == "" {
		http.NotFound(w, r)
		return
	}
	a.beginSocial(w, r, "")
}

func (a *Auth) startLinkSocial(w http.ResponseWriter, r *http.Request) {
	if a.ssoOrganizations[r.PathValue("provider")] != "" {
		http.NotFound(w, r)
		return
	}
	a.linkSocial(w, r)
}

func (a *Auth) startLinkSSO(w http.ResponseWriter, r *http.Request) {
	if a.ssoOrganizations[r.PathValue("provider")] == "" {
		http.NotFound(w, r)
		return
	}
	a.linkSocial(w, r)
}

func (a *Auth) linkSocial(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Origin") != a.config.BaseURL {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	a.beginSocial(w, r, p.Subject)
}

type socialState struct {
	Pending    social.Pending
	LinkUserID string
}

func (a *Auth) beginSocial(w http.ResponseWriter, r *http.Request, linkUserID string) {
	name := r.PathValue("provider")
	p := a.providers[name]
	if p == nil {
		http.NotFound(w, r)
		return
	}
	url, pending, err := p.Begin()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	payload, err := json.Marshal(socialState{Pending: pending, LinkUserID: linkUserID})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	id, err := randomID("flow_")
	if err == nil {
		err = a.config.Storage.Flows.Put(r.Context(), id, "social:"+name, payload, time.Now().Add(oauthStateTTL))
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setFlowCookie(w, name, id, int(oauthStateTTL.Seconds()), name == social.Apple)
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *Auth) finishSocial(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	p := a.providers[name]
	if p == nil {
		http.NotFound(w, r)
		return
	}
	cookie, err := r.Cookie(flowCookieName(name))
	a.setFlowCookie(w, name, "", -1, name == social.Apple)
	if err != nil {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	payload, found, err := a.config.Storage.Flows.Take(r.Context(), cookie.Value, "social:"+name)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	var flow socialState
	if err := json.Unmarshal(payload, &flow); err != nil {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	person, err := p.Complete(r.Context(), flow.Pending, r.FormValue("state"), r.FormValue("code"))
	if err != nil {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	if domain := a.ssoDomains[name]; domain != "" {
		if !validSSOEmail(person, domain) {
			http.Error(w, "organization email was not verified by the identity provider", http.StatusForbidden)
			return
		}
	}
	if flow.LinkUserID != "" {
		if err := a.Social.Link(r.Context(), identity.Principal{Kind: identity.KindUser, Subject: flow.LinkUserID}, person); err != nil {
			http.Error(w, "unable to link social account", http.StatusConflict)
			return
		}
		if err := a.ensureSSOMembership(r.Context(), name, flow.LinkUserID); err != nil {
			http.Error(w, "unable to add organization membership", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, a.config.BaseURL+"/?authkit_linked="+name, http.StatusSeeOther)
		return
	}
	userID, err := a.Social.Resolve(r.Context(), person)
	if errors.Is(err, identity.ErrEmailInUse) {
		http.Error(w, "email already belongs to another account; sign in and link this provider", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "unable to sign in", http.StatusInternalServerError)
		return
	}
	if err := a.ensureSSOMembership(r.Context(), name, userID); err != nil {
		http.Error(w, "unable to add organization membership", http.StatusInternalServerError)
		return
	}
	mfaRequired, err := a.issueSessionOrChallenge(w, r, userID)
	if err != nil {
		http.Error(w, "unable to sign in", http.StatusInternalServerError)
		return
	}
	if mfaRequired {
		http.Redirect(w, r, a.config.BaseURL+"/?authkit_mfa=required", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, a.config.BaseURL+"/", http.StatusSeeOther)
}

func validSSOEmail(person identity.SocialIdentity, domain string) bool {
	parts := strings.Split(strings.ToLower(person.Email), "@")
	return person.EmailVerified && len(parts) == 2 && parts[0] != "" && parts[1] == domain
}

func (a *Auth) currentSession(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"principal": p})
}

func (a *Auth) signOut(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		_ = a.Sessions.Logout(r.Context(), cookie.Value)
	}
	a.clearSession(w)
	a.clearMFAChallenge(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) completeTwoFactor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Challenge == "" {
		if cookie, err := r.Cookie("authkit.mfa"); err == nil {
			body.Challenge = cookie.Value
		}
	}
	token, err := a.Password.CompleteMFA(r.Context(), body.Challenge, body.Code)
	if err != nil {
		http.Error(w, "invalid challenge or code", http.StatusUnauthorized)
		return
	}
	a.setSession(w, token)
	a.clearMFAChallenge(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) enrollTwoFactor(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if enrolled, err := a.TwoFactor.IsEnrolled(r.Context(), p.Subject); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	} else if enrolled {
		http.Error(w, "two-factor already enabled", http.StatusConflict)
		return
	}
	user, err := a.config.Storage.Users.GetByID(r.Context(), p.Subject)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secret, uri, err := a.TwoFactor.BeginEnrolment(r.Context(), p.Subject, a.config.BaseURL, user.Email)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": uri})
}

func (a *Auth) confirmTwoFactor(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.TwoFactor.ConfirmEnrolment(r.Context(), p.Subject, body.Code, time.Now()); err != nil {
		http.Error(w, "invalid code", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) principal(r *http.Request) (identity.Principal, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return identity.Principal{}, false
	}
	return a.Sessions.Resolve(r.Context(), cookie.Value)
}

func (a *Auth) setSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: 30 * 24 * 60 * 60})
}

func (a *Auth) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (a *Auth) issueSessionOrChallenge(w http.ResponseWriter, r *http.Request, userID string) (bool, error) {
	result, err := a.signInUser(r.Context(), userID)
	if err != nil {
		return false, err
	}
	if result.MFARequired {
		a.setMFAChallenge(w, result.Challenge)
		return true, nil
	}
	a.setSession(w, result.Session)
	return false, nil
}

func (a *Auth) setMFAChallenge(w http.ResponseWriter, challenge string) {
	http.SetCookie(w, &http.Cookie{Name: "authkit.mfa", Value: challenge, Path: a.basePath + "/two-factor/complete",
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: 5 * 60})
}

func (a *Auth) clearMFAChallenge(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: "authkit.mfa", Path: a.basePath + "/two-factor/complete",
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func flowCookieName(provider string) string { return "authkit.oauth." + provider }

func (a *Auth) setFlowCookie(w http.ResponseWriter, provider, value string, age int, crossSite bool) {
	sameSite := http.SameSiteLaxMode
	if crossSite {
		sameSite = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookieName(provider), Value: value,
		Path: a.basePath + "/callback/" + provider, HttpOnly: true, Secure: a.secure,
		SameSite: sameSite, MaxAge: age})
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}
