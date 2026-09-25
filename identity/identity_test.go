package identity_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/goat-io/authkit/identity"
	"github.com/goat-io/authkit/token/eddsa"
)

type memStore struct {
	mu sync.Mutex
	m  map[string]identity.Credential
}

func newMem() *memStore { return &memStore{m: map[string]identity.Credential{}} }
func (s *memStore) Create(_ context.Context, c identity.Credential) error {
	s.mu.Lock(); defer s.mu.Unlock(); s.m[c.SecretHash] = c; return nil
}
func (s *memStore) GetByHash(_ context.Context, h string) (identity.Credential, error) {
	s.mu.Lock(); defer s.mu.Unlock()
	if c, ok := s.m[h]; ok { return c, nil }
	return identity.Credential{}, identity.ErrInvalidCredential
}
func (s *memStore) Bind(_ context.Context, id, sub string) error {
	s.mu.Lock(); defer s.mu.Unlock()
	for h, c := range s.m { if c.ID == id { c.Subject = sub; s.m[h] = c } }
	return nil
}
func (s *memStore) Touch(context.Context, string) error { return nil }
func (s *memStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock(); defer s.mu.Unlock()
	now := time.Now()
	for h, c := range s.m { if c.ID == id { c.RevokedAt = &now; s.m[h] = c } }
	return nil
}
func (s *memStore) List(context.Context, string) ([]identity.Credential, error) { return nil, nil }

func TestCredentialExchangeAndAuthenticate(t *testing.T) {
	signer, _, err := eddsa.Generate()
	if err != nil { t.Fatal(err) }
	svc := identity.NewCredentialService(newMem(), signer, time.Minute)
	auth := identity.NewAuthenticator("admin-tok", signer)
	ctx := context.Background()

	secret, cred, err := svc.Mint(ctx, "org1", "runner", []string{"runner"})
	if err != nil { t.Fatal(err) }
	jwt, _, err := svc.Exchange(ctx, secret, "r1", 0)
	if err != nil { t.Fatalf("exchange: %v", err) }

	p := auth.Authenticate(context.Background(), jwt)
	if p.Kind != identity.KindMachine || p.Subject != "r1" || p.OrgID != "org1" {
		t.Fatalf("bad principal: %+v", p)
	}
	if auth.Authenticate(context.Background(), "admin-tok").Kind != identity.KindAdmin { t.Fatal("admin not recognized") }
	if auth.Authenticate(context.Background(), "nope").Authenticated() { t.Fatal("unknown token should be anonymous") }
	if _, _, err := svc.Exchange(ctx, secret, "r2", 0); err != identity.ErrWrongSubject {
		t.Fatalf("expected ErrWrongSubject, got %v", err)
	}
	_ = svc.Revoke(ctx, cred.ID)
	if _, _, err := svc.Exchange(ctx, secret, "r1", 0); err != identity.ErrRevoked {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}
