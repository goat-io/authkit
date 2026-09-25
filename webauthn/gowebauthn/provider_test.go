package gowebauthn_test

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/goat-io/authkit/identity"
	"github.com/goat-io/authkit/webauthn/gowebauthn"
)

// memWebAuthnStore is an in-memory WebAuthnCredentialStore for tests.
type memWebAuthnStore struct {
	mu   sync.Mutex
	byID map[string]identity.WebAuthnCredential
}

func newMemStore() *memWebAuthnStore {
	return &memWebAuthnStore{byID: map[string]identity.WebAuthnCredential{}}
}

func (m *memWebAuthnStore) Add(_ context.Context, c identity.WebAuthnCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[string(c.ID)] = c
	return nil
}

func (m *memWebAuthnStore) ListByUser(_ context.Context, userID string) ([]identity.WebAuthnCredential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []identity.WebAuthnCredential
	for _, c := range m.byID {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *memWebAuthnStore) Delete(_ context.Context, _ string, id []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, string(id))
	return nil
}

func (m *memWebAuthnStore) UpdateSignCount(_ context.Context, id []byte, n uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[string(id)]
	if !ok {
		return nil
	}
	c.SignCount = n
	m.byID[string(id)] = c
	return nil
}

func newProvider(t *testing.T) *gowebauthn.Provider {
	t.Helper()
	p, err := gowebauthn.New(gowebauthn.Config{
		RPID:          "delphi.local",
		RPDisplayName: "Delphi",
		RPOrigins:     []string{"https://delphi.local"},
	}, newMemStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestBeginRegistrationProducesOptionsAndSession(t *testing.T) {
	p := newProvider(t)
	u := identity.User{ID: "user_123", Email: "a@b.com", DisplayName: "Ada"}

	options, session, err := p.BeginRegistration(context.Background(), u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	// options must be valid creation JSON carrying a challenge + our RP id.
	var opt struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opt); err != nil {
		t.Fatalf("options not JSON: %v", err)
	}
	if opt.PublicKey.Challenge == "" {
		t.Fatal("no challenge in creation options")
	}
	if opt.PublicKey.RP.ID != "delphi.local" {
		t.Fatalf("rp id = %q, want delphi.local", opt.PublicKey.RP.ID)
	}
	if opt.PublicKey.User.ID == "" {
		t.Fatal("no user id in creation options")
	}
	// session blob must round-trip the challenge so a later pod can finish.
	if len(session) == 0 || !bytes.Contains(session, []byte("challenge")) {
		t.Fatalf("session blob missing challenge: %s", session)
	}
}

func TestBeginLoginProducesOptionsAndSession(t *testing.T) {
	store := newMemStore()
	p, err := gowebauthn.New(gowebauthn.Config{
		RPID:          "delphi.local",
		RPDisplayName: "Delphi",
		RPOrigins:     []string{"https://delphi.local"},
	}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u := identity.User{ID: "user_42", Email: "c@d.com"}

	// Seed a stored passkey so BeginLogin has an allowed credential.
	if err := store.Add(context.Background(), identity.WebAuthnCredential{
		ID:         []byte("cred-abc"),
		UserID:     u.ID,
		PublicKey:  []byte{1, 2, 3, 4},
		SignCount:  7,
		Transports: []string{"internal", "hybrid"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	options, session, err := p.BeginLogin(context.Background(), u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	var opt struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			AllowCredentials []struct {
				ID string `json:"id"`
			} `json:"allowCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &opt); err != nil {
		t.Fatalf("options not JSON: %v", err)
	}
	if opt.PublicKey.Challenge == "" {
		t.Fatal("no challenge in request options")
	}
	if len(opt.PublicKey.AllowCredentials) != 1 {
		t.Fatalf("allowCredentials = %d, want 1", len(opt.PublicKey.AllowCredentials))
	}
	if len(session) == 0 {
		t.Fatal("empty login session blob")
	}
}
