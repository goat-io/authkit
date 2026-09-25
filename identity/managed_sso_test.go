package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memorySSOStore struct {
	connection SSOConnection
	exists     bool
}

func (s *memorySSOStore) SaveSSO(_ context.Context, c SSOConnection) error {
	s.connection = c
	s.exists = true
	return nil
}
func (s *memorySSOStore) GetSSOByOrg(_ context.Context, org string) (SSOConnection, bool, error) {
	return s.connection, s.exists && s.connection.OrgID == org, nil
}
func (s *memorySSOStore) GetSSOByDomain(_ context.Context, domain string) (SSOConnection, bool, error) {
	return s.connection, s.exists && s.connection.Domain == domain && s.connection.VerifiedAt != nil, nil
}
func (s *memorySSOStore) ListVerifiedSSO(context.Context) ([]SSOConnection, error) {
	if s.exists && s.connection.VerifiedAt != nil {
		return []SSOConnection{s.connection}, nil
	}
	return nil, nil
}
func (s *memorySSOStore) VerifySSO(_ context.Context, org, token string) error {
	if !s.exists || s.connection.OrgID != org || s.connection.VerificationToken != token {
		return errors.New("changed")
	}
	now := s.connection.VerifiedAt
	if now == nil {
		v := time.Now()
		now = &v
	}
	s.connection.VerifiedAt = now
	return nil
}
func (s *memorySSOStore) DeleteSSO(context.Context, string) error { s.exists = false; return nil }

func TestManagedSSODomainProofAndDiscovery(t *testing.T) {
	ctx := context.Background()
	store := &memorySSOStore{}
	m, err := NewManagedSSO(store, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	owner := Principal{Kind: KindUser, Subject: "user", Memberships: []Membership{{OrgID: "org1", Role: "owner"}}}
	member := Principal{Kind: KindUser, Subject: "other", Memberships: []Membership{{OrgID: "org1", Role: "member"}}}
	input := SSOConnection{OrgID: "org1", Domain: "Example.COM", IssuerURL: "https://idp.example.com", ClientID: "client", ClientSecret: "secret"}
	if _, err := m.Configure(ctx, member, input); err == nil {
		t.Fatal("member configured SSO")
	}
	c, err := m.Configure(ctx, owner, input)
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientSecret != "" || store.connection.ClientSecret == "secret" {
		t.Fatal("client secret leaked or stored unencrypted")
	}
	if id, err := m.Discover(ctx, "person@example.com"); err != nil || id != "" {
		t.Fatalf("unverified domain discoverable: %q %v", id, err)
	}
	m.lookupTXT = func(context.Context, string) ([]string, error) { return []string{"wrong"}, nil }
	if _, err := m.Verify(ctx, owner, "org1"); err == nil {
		t.Fatal("incorrect DNS record verified")
	}
	m.lookupTXT = func(_ context.Context, name string) ([]string, error) {
		if name != "_authkit-sso.example.com" {
			t.Fatal(name)
		}
		return []string{c.VerificationToken}, nil
	}
	if _, err := m.Verify(ctx, owner, "org1"); err != nil {
		t.Fatal(err)
	}
	if id, err := m.Discover(ctx, "person@EXAMPLE.COM"); err != nil || id != "org1" {
		t.Fatalf("verified discovery: %q %v", id, err)
	}
	active, err := m.Active(ctx)
	if err != nil || len(active) != 1 || active[0].ClientSecret != "secret" {
		t.Fatalf("active: %+v %v", active, err)
	}
	if _, err := m.Configure(ctx, owner, input); err != nil {
		t.Fatal(err)
	}
	if id, _ := m.Discover(ctx, "person@example.com"); id != "" {
		t.Fatal("reconfiguration retained verification")
	}
	if err := m.Delete(ctx, member, "org1"); err == nil {
		t.Fatal("member deleted SSO")
	}
}
