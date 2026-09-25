package authkit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/goat-io/authkit/social"
	"github.com/goat-io/authkit/token/eddsa"
)

type memory struct {
	mu       sync.Mutex
	users    map[string]identity.User
	sessions map[string]identity.Session
	flows    map[string][]byte
	accounts map[string]string
	mfa      map[string]identity.MFAEnrolment
}

func newMemory() *memory {
	return &memory{users: map[string]identity.User{}, sessions: map[string]identity.Session{}, flows: map[string][]byte{}, accounts: map[string]string{}, mfa: map[string]identity.MFAEnrolment{}}
}
func (m *memory) Create(_ context.Context, u identity.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if existing.Email == u.Email {
			return errors.New("duplicate email")
		}
	}
	m.users[u.ID] = u
	return nil
}
func (m *memory) GetByEmail(_ context.Context, email string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return identity.User{}, errors.New("missing user")
}
func (m *memory) GetByID(_ context.Context, id string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return identity.User{}, errors.New("missing user")
	}
	return u, nil
}
func (m *memory) CreateSession(_ context.Context, s identity.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = s
	return nil
}
func (m *memory) Lookup(_ context.Context, hash string) (identity.Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	return s, ok, nil
}
func (m *memory) Delete(_ context.Context, hash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hash)
	return nil
}

type sessionMemory struct{ *memory }

func (s sessionMemory) Create(ctx context.Context, value identity.Session) error {
	return s.CreateSession(ctx, value)
}
func (m *memory) Put(_ context.Context, id, kind string, payload []byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[kind+":"+id] = payload
	return nil
}
func (m *memory) Take(_ context.Context, id, kind string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := kind + ":" + id
	value, ok := m.flows[key]
	delete(m.flows, key)
	return value, ok, nil
}
func (m *memory) ResolveOrCreate(_ context.Context, p identity.SocialIdentity) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := p.Provider + ":" + p.Subject
	if id := m.accounts[key]; id != "" {
		return id, nil
	}
	id := "social-user"
	m.accounts[key] = id
	m.users[id] = identity.User{ID: id, Email: p.Email}
	return id, nil
}
func (m *memory) Link(_ context.Context, id string, p identity.SocialIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts[p.Provider+":"+p.Subject] = id
	return nil
}
func (m *memory) Get(_ context.Context, subject string) (identity.MFAEnrolment, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.mfa[subject]
	return value, ok, nil
}
func (m *memory) Upsert(_ context.Context, subject string, value identity.MFAEnrolment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mfa[subject] = value
	return nil
}
func (m *memory) Activate(_ context.Context, subject string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value := m.mfa[subject]
	value.Active = true
	m.mfa[subject] = value
	return nil
}

func makeAuth(t *testing.T) (*Auth, *memory) {
	t.Helper()
	m := newMemory()
	a, err := New(context.Background(), Config{BaseURL: "http://localhost:3000", Storage: Storage{Users: m, Sessions: sessionMemory{m}, Flows: m, SocialAccounts: m}, EmailAndPassword: EmailAndPassword{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	return a, m
}

func request(handler http.Handler, method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestConfiguredEmailRoutesAndMiddleware(t *testing.T) {
	a, _ := makeAuth(t)
	handler := a.Handler()
	created := request(handler, http.MethodPost, "/api/auth/sign-up/email", `{"email":"User@Example.com","password":"password123","name":"Test User"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", created.Code, created.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range created.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatal("session cookie missing")
	}
	session := request(handler, http.MethodGet, "/api/auth/session", "", cookie)
	if session.Code != http.StatusOK || !bytes.Contains(session.Body.Bytes(), []byte(`"kind":2`)) {
		t.Fatalf("session: %d %s", session.Code, session.Body.String())
	}
	var principal identity.Principal
	a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { principal, _ = PrincipalFrom(r.Context()) })).ServeHTTP(httptest.NewRecorder(), func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/private", nil)
		r.AddCookie(cookie)
		return r
	}())
	if principal.Kind != identity.KindUser {
		t.Fatalf("middleware principal: %+v", principal)
	}
	if got := request(handler, http.MethodPost, "/api/auth/sign-out", "", cookie); got.Code != http.StatusOK {
		t.Fatalf("sign out: %d", got.Code)
	}
	if got := request(handler, http.MethodGet, "/api/auth/session", "", cookie); got.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session: %d", got.Code)
	}
	login := request(handler, http.MethodPost, "/api/auth/sign-in/email", `{"email":"user@example.com","password":"password123"}`)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
}

func TestHTTPSessionCookieCannotBeSetBySiblingSubdomain(t *testing.T) {
	m := newMemory()
	a, err := New(context.Background(), Config{BaseURL: "https://terminal.azdelphi.com", Storage: Storage{Users: m, Sessions: sessionMemory{m}, Flows: m, SocialAccounts: m}, EmailAndPassword: EmailAndPassword{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	handler := a.Handler()
	created := request(handler, http.MethodPost, "/api/auth/sign-up/email", `{"email":"user@example.com","password":"password123","name":"Test User"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("signup: %d %s", created.Code, created.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range created.Result().Cookies() {
		if c.Name == hostSessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("HTTPS session must be host-bound: %+v", cookie)
	}
	legacy := *cookie
	legacy.Name = sessionCookie
	if got := request(handler, http.MethodGet, "/api/auth/session", "", &legacy); got.Code != http.StatusUnauthorized {
		t.Fatalf("legacy parent-domain cookie authenticated: %d", got.Code)
	}
	if got := request(handler, http.MethodGet, "/api/auth/session", "", cookie); got.Code != http.StatusOK {
		t.Fatalf("host-bound cookie failed: %d", got.Code)
	}
}

type fakeSocial struct{}

func (fakeSocial) Begin() (string, social.Pending, error) {
	return "https://provider.example/authorize", social.Pending{State: "state", Nonce: "nonce", CreatedAt: time.Now()}, nil
}
func (fakeSocial) Complete(_ context.Context, p social.Pending, state, code string) (identity.SocialIdentity, error) {
	if p.State != state || code != "code" {
		return identity.SocialIdentity{}, social.ErrInvalidCallback
	}
	return identity.SocialIdentity{Provider: social.Google, Subject: "sub-1", Email: "social@example.com", EmailVerified: true}, nil
}

func TestSocialCallbackConsumesFlow(t *testing.T) {
	a, m := makeAuth(t)
	a.Social = identity.NewSocialLoginService(m, a.Sessions)
	a.providers[social.Google] = fakeSocial{}
	handler := a.Handler()
	start := request(handler, http.MethodGet, "/api/auth/sign-in/social/google", "")
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d", start.Code)
	}
	var flow *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == flowCookieName(social.Google) {
			flow = c
		}
	}
	if flow == nil || flow.Value == "" {
		t.Fatal("flow cookie missing")
	}
	callback := request(handler, http.MethodGet, "/api/auth/callback/google?state=state&code=code", "", flow)
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback: %d %s", callback.Code, callback.Body.String())
	}
	replay := request(handler, http.MethodGet, "/api/auth/callback/google?state=state&code=code", "", flow)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay: %d", replay.Code)
	}
	var sessionCookieValue *http.Cookie
	for _, c := range callback.Result().Cookies() {
		if c.Name == sessionCookie {
			sessionCookieValue = c
		}
	}
	if sessionCookieValue == nil {
		t.Fatal("social session missing")
	}
	var response map[string]json.RawMessage
	got := request(handler, http.MethodGet, "/api/auth/session", "", sessionCookieValue)
	if err := json.Unmarshal(got.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if got.Code != http.StatusOK {
		t.Fatalf("session: %d", got.Code)
	}
	linkStart := httptest.NewRequest(http.MethodPost, "/api/auth/link/social/google", nil)
	linkStart.AddCookie(sessionCookieValue)
	linkStart.Header.Set("Origin", "http://localhost:3000")
	linkResponse := httptest.NewRecorder()
	handler.ServeHTTP(linkResponse, linkStart)
	if linkResponse.Code != http.StatusFound {
		t.Fatalf("link start: %d %s", linkResponse.Code, linkResponse.Body.String())
	}
	var linkFlow *http.Cookie
	for _, c := range linkResponse.Result().Cookies() {
		if c.Name == flowCookieName(social.Google) {
			linkFlow = c
		}
	}
	if linkFlow == nil {
		t.Fatal("link flow cookie missing")
	}
	if got := request(handler, http.MethodGet, "/api/auth/callback/google?state=state&code=code", "", linkFlow); got.Code != http.StatusSeeOther {
		t.Fatalf("link callback: %d %s", got.Code, got.Body.String())
	}
}

func TestHTTPSocialFlowCookieCannotBeSetBySiblingSubdomain(t *testing.T) {
	m := newMemory()
	a, err := New(context.Background(), Config{BaseURL: "https://terminal.azdelphi.com", Storage: Storage{Users: m, Sessions: sessionMemory{m}, Flows: m, SocialAccounts: m}, EmailAndPassword: EmailAndPassword{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	a.Social = identity.NewSocialLoginService(m, a.Sessions)
	a.providers[social.Google] = fakeSocial{}
	handler := a.Handler()
	start := request(handler, http.MethodGet, "/api/auth/sign-in/social/google", "")
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Body.String())
	}
	var flow *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == "__Host-"+flowCookieName(social.Google) {
			flow = c
		}
	}
	if flow == nil || flow.Value == "" || !flow.Secure || !flow.HttpOnly || flow.Path != "/" || flow.Domain != "" {
		t.Fatalf("HTTPS flow must be host-bound: %+v", flow)
	}
	legacy := *flow
	legacy.Name = flowCookieName(social.Google)
	if got := request(handler, http.MethodGet, "/api/auth/callback/google?state=state&code=code", "", &legacy); got.Code != http.StatusBadRequest {
		t.Fatalf("parent-domain cookie accepted: %d", got.Code)
	}
	if got := request(handler, http.MethodGet, "/api/auth/callback/google?state=state&code=code", "", flow); got.Code != http.StatusSeeOther {
		t.Fatalf("host-bound cookie rejected: %d %s", got.Code, got.Body.String())
	}
}

func TestSocialSignInRequiresConfiguredMFA(t *testing.T) {
	m := newMemory()
	signer, _, err := eddsa.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(context.Background(), Config{BaseURL: "http://localhost:3000", Signer: signer,
		Storage:          Storage{Users: m, Sessions: sessionMemory{m}, Flows: m, SocialAccounts: m, MFA: m},
		EmailAndPassword: EmailAndPassword{Enabled: true}, Plugins: []Plugin{TwoFactor()}})
	if err != nil {
		t.Fatal(err)
	}
	a.Social = identity.NewSocialLoginService(m, a.Sessions)
	a.providers[social.Google] = fakeSocial{}
	m.mfa["social-user"] = identity.MFAEnrolment{Secret: "JBSWY3DPEHPK3PXP", Active: true}
	handler := a.Handler()
	start := request(handler, http.MethodGet, "/api/auth/sign-in/social/google", "")
	var flow *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == flowCookieName(social.Google) {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("flow missing")
	}
	callback := request(handler, http.MethodGet, "/api/auth/callback/google?state=state&code=code", "", flow)
	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback: %d %s", callback.Code, callback.Body.String())
	}
	var challenge *http.Cookie
	for _, c := range callback.Result().Cookies() {
		if c.Name == sessionCookie {
			t.Fatal("session issued before MFA")
		}
		if c.Name == "authkit.mfa" {
			challenge = c
		}
	}
	if challenge == nil {
		t.Fatal("MFA challenge missing")
	}
	if a.Authenticator.Authenticate(context.Background(), challenge.Value).Authenticated() {
		t.Fatal("challenge authenticated as machine")
	}
	code := testTOTP(t, "JBSWY3DPEHPK3PXP", time.Now())
	complete := request(handler, http.MethodPost, "/api/auth/two-factor/complete", `{"code":"`+code+`"}`, challenge)
	if complete.Code != http.StatusOK {
		t.Fatalf("MFA completion: %d %s", complete.Code, complete.Body.String())
	}
	var session *http.Cookie
	for _, c := range complete.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("session missing after MFA")
	}
}

func testTOTP(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 | uint32(sum[offset+1])<<16 | uint32(sum[offset+2])<<8 | uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000)
}
