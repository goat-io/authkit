package authkit

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/goat-io/authkit/identity"
)

type passkeyFlow struct {
	UserID  string
	Session []byte
}

const passkeyFlowTTL = 5 * time.Minute

func (a *Auth) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	p, ok := a.principal(r)
	if !ok || p.Kind != identity.KindUser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := a.config.Storage.Users.GetByID(r.Context(), p.Subject)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	options, ceremony, err := a.Passkeys.BeginRegistration(r.Context(), user)
	if err != nil {
		http.Error(w, "unable to start registration", http.StatusBadRequest)
		return
	}
	if err := a.savePasskeyFlow(w, r, "register", passkeyFlow{UserID: user.ID, Session: ceremony}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeOptions(w, options)
}

func (a *Auth) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	flow, ok := a.takePasskeyFlow(w, r, "register")
	if !ok {
		return
	}
	p, authenticated := a.principal(r)
	if !authenticated || p.Kind != identity.KindUser || p.Subject != flow.UserID {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	response, ok := readCeremonyResponse(w, r)
	if !ok {
		return
	}
	user, err := a.config.Storage.Users.GetByID(r.Context(), flow.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := a.Passkeys.FinishRegistration(r.Context(), user, flow.Session, response); err != nil {
		http.Error(w, "invalid passkey response", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) beginPasskeySignIn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	user, err := a.config.Storage.Users.GetByEmail(r.Context(), strings.ToLower(strings.TrimSpace(body.Email)))
	if err != nil {
		http.Error(w, "unable to start sign-in", http.StatusUnauthorized)
		return
	}
	options, ceremony, err := a.Passkeys.BeginLogin(r.Context(), user)
	if err != nil {
		http.Error(w, "unable to start sign-in", http.StatusUnauthorized)
		return
	}
	if err := a.savePasskeyFlow(w, r, "sign-in", passkeyFlow{UserID: user.ID, Session: ceremony}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeOptions(w, options)
}

func (a *Auth) finishPasskeySignIn(w http.ResponseWriter, r *http.Request) {
	flow, ok := a.takePasskeyFlow(w, r, "sign-in")
	if !ok {
		return
	}
	response, ok := readCeremonyResponse(w, r)
	if !ok {
		return
	}
	user, err := a.config.Storage.Users.GetByID(r.Context(), flow.UserID)
	if err != nil {
		http.Error(w, "invalid passkey response", http.StatusBadRequest)
		return
	}
	userID, err := a.Passkeys.FinishLogin(r.Context(), user, flow.Session, response)
	if err != nil || userID != flow.UserID {
		http.Error(w, "invalid passkey response", http.StatusUnauthorized)
		return
	}
	mfaRequired, err := a.issueSessionOrChallenge(w, r, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if mfaRequired {
		writeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) savePasskeyFlow(w http.ResponseWriter, r *http.Request, kind string, flow passkeyFlow) error {
	payload, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	id, err := randomID("flow_")
	if err != nil {
		return err
	}
	if err := a.config.Storage.Flows.Put(r.Context(), id, "passkey:"+kind, payload, time.Now().Add(passkeyFlowTTL)); err != nil {
		return err
	}
	a.setPasskeyCookie(w, kind, id, int(passkeyFlowTTL.Seconds()))
	return nil
}

func (a *Auth) takePasskeyFlow(w http.ResponseWriter, r *http.Request, kind string) (passkeyFlow, bool) {
	var flow passkeyFlow
	cookie, err := r.Cookie("authkit.passkey." + kind)
	a.setPasskeyCookie(w, kind, "", -1)
	if err != nil {
		http.Error(w, "missing passkey challenge", http.StatusBadRequest)
		return flow, false
	}
	payload, found, err := a.config.Storage.Flows.Take(r.Context(), cookie.Value, "passkey:"+kind)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return flow, false
	}
	if !found || json.Unmarshal(payload, &flow) != nil || flow.UserID == "" || len(flow.Session) == 0 {
		http.Error(w, "invalid passkey challenge", http.StatusBadRequest)
		return flow, false
	}
	return flow, true
}

func (a *Auth) setPasskeyCookie(w http.ResponseWriter, kind, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "authkit.passkey." + kind, Value: value,
		Path: a.basePath + "/passkey/", MaxAge: age, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

func readCeremonyResponse(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	b, err := io.ReadAll(r.Body)
	if err != nil || len(b) == 0 || !json.Valid(b) {
		http.Error(w, "invalid passkey response", http.StatusBadRequest)
		return nil, false
	}
	return b, true
}

func writeOptions(w http.ResponseWriter, options []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(options)
}
