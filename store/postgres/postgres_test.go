package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/goat-io/authkit/identity"
	pgstore "github.com/goat-io/authkit/store/postgres"
	"github.com/goat-io/authkit/token/eddsa"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://delphi:delphi@localhost:5434/delphi_test?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Skipf("no test Postgres: %v", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		t.Skipf("test Postgres unreachable: %v", err)
	}
	schema := "ak_" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+schema+"; SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	// pgxpool runs each query on any conn; pin search_path via a fresh pool DSN.
	pool.Close()
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pool, err = pgxpool.New(ctx, dsn+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		pool.Close()
	})
	if err := pgstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPostgresMachineAndUserPaths(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	signer, _, _ := eddsa.Generate()

	// --- machine path: credential → exchange → JWT → authenticate ---
	creds := identity.NewCredentialService(pgstore.NewCredentials(pool), signer, time.Minute)
	auth := identity.NewAuthenticator("admin", signer)
	secret, _, err := creds.Mint(ctx, "org1", "runner", []string{"runner"})
	if err != nil {
		t.Fatal(err)
	}
	jwt, _, err := creds.Exchange(ctx, secret, "r1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if p := auth.Authenticate(ctx, jwt); p.Kind != identity.KindMachine || p.Subject != "r1" || p.OrgID != "org1" {
		t.Fatalf("machine principal wrong: %+v", p)
	}

	// --- user path: create → membership → login → session → resolve ---
	users := pgstore.NewUsers(pool)
	mem := pgstore.NewMemberships(pool)
	sessions := pgstore.NewSessions(pool)
	pwHash, _ := identity.HashPassword("hunter2")
	if err := users.Create(ctx, identity.User{ID: "u1", Email: "a@b.co", PasswordHash: pwHash, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_ = mem.Add(ctx, "u1", "org1", "owner")
	sessSvc := identity.NewSessionService(sessions, users, mem, time.Hour)
	auth = auth.WithSessions(sessSvc)

	tok, err := sessSvc.Login(ctx, "a@b.co", "hunter2")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	p := auth.Authenticate(ctx, tok)
	if p.Kind != identity.KindUser || p.Subject != "u1" || p.OrgID != "org1" || len(p.Memberships) != 1 {
		t.Fatalf("user principal wrong: %+v", p)
	}
	// wrong password rejected
	if _, err := sessSvc.Login(ctx, "a@b.co", "nope"); err != identity.ErrInvalidLogin {
		t.Fatalf("expected ErrInvalidLogin, got %v", err)
	}
	// logout invalidates the session
	_ = sessSvc.Logout(ctx, tok)
	if auth.Authenticate(ctx, tok).Authenticated() {
		t.Fatal("session should be invalid after logout")
	}
}

func TestPostgresWebAuthnCredentials(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	store := pgstore.NewWebAuthnCredentials(pool)

	cred := identity.WebAuthnCredential{
		ID:              []byte{0xDE, 0xAD, 0xBE, 0xEF},
		UserID:          "u1",
		PublicKey:       []byte{1, 2, 3, 4, 5},
		AttestationType: "none",
		AAGUID:          []byte{0xAA, 0xBB},
		SignCount:       3,
		Transports:      []string{"internal", "hybrid"},
		CreatedAt:       time.Now().UTC(),
	}
	if err := store.Add(ctx, cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, err := store.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	g := got[0]
	if string(g.ID) != string(cred.ID) || g.UserID != "u1" || g.SignCount != 3 {
		t.Fatalf("roundtrip mismatch: %+v", g)
	}
	if len(g.Transports) != 2 || g.Transports[0] != "internal" {
		t.Fatalf("transports mismatch: %v", g.Transports)
	}
	if string(g.PublicKey) != string(cred.PublicKey) {
		t.Fatalf("public key mismatch")
	}

	// clone detection: sign count advances
	if err := store.UpdateSignCount(ctx, cred.ID, 9); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	got, _ = store.ListByUser(ctx, "u1")
	if got[0].SignCount != 9 {
		t.Fatalf("sign count = %d, want 9", got[0].SignCount)
	}

	// other users see nothing
	if other, _ := store.ListByUser(ctx, "nobody"); len(other) != 0 {
		t.Fatalf("expected no creds for other user, got %d", len(other))
	}
}

func TestPostgresMFAAndRecovery(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	mfa := identity.NewMFAService(pgstore.NewMFA(pool)).WithRecoveryStore(pgstore.NewMFARecovery(pool))

	// Activate before any enrolment → not enrolled.
	if err := pgstore.NewMFA(pool).Activate(ctx, "ghost"); err != identity.ErrMFANotEnrolled {
		t.Fatalf("activate ghost: want ErrMFANotEnrolled, got %v", err)
	}

	secret, _, err := mfa.BeginEnrolment(ctx, "u1", "Delphi", "a@b.co")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if ok, _ := mfa.IsEnrolled(ctx, "u1"); ok {
		t.Fatal("pending enrolment should not count")
	}
	// confirm with a live code (found via ValidateTOTP, see liveCode)
	code := liveCode(secret, now)
	if err := mfa.ConfirmEnrolment(ctx, "u1", code, now); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if ok, _ := mfa.IsEnrolled(ctx, "u1"); !ok {
		t.Fatal("should be enrolled after confirm")
	}
	if err := mfa.Verify(ctx, "u1", code, now); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// recovery codes: single-use, persisted across store instances
	codes, err := mfa.GenerateRecoveryCodes(ctx, "u1")
	if err != nil {
		t.Fatalf("gen recovery: %v", err)
	}
	fresh := identity.NewMFAService(pgstore.NewMFA(pool)).WithRecoveryStore(pgstore.NewMFARecovery(pool))
	if ok, err := fresh.VerifyRecoveryCode(ctx, "u1", codes[0]); !ok || err != nil {
		t.Fatalf("recovery first use: ok=%v err=%v", ok, err)
	}
	if ok, _ := fresh.VerifyRecoveryCode(ctx, "u1", codes[0]); ok {
		t.Fatal("recovery code should be single-use")
	}
}

// liveCode finds the valid TOTP for secret at now by brute-forcing the 6-digit
// space against identity.ValidateTOTP — fine for a test, no internal access needed.
func liveCode(secret string, now time.Time) string {
	for i := 0; i < 1_000_000; i++ {
		c := fmt.Sprintf("%06d", i)
		if identity.ValidateTOTP(secret, c, now) {
			return c
		}
	}
	return ""
}
