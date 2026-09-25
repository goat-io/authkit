package postgres_test

import (
	"context"
	"testing"
	"time"

	pgstore "github.com/goat-io/authkit/store/postgres"
)

func TestFlowsConsumeOnceAndExpire(t *testing.T) {
	pool := testPool(t)
	flows := pgstore.NewFlows(pool)
	ctx := context.Background()
	if err := flows.Put(ctx, "one", "social:google", []byte("challenge"), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := flows.Take(ctx, "one", "social:apple"); err != nil || ok {
		t.Fatalf("wrong kind: %v %v", ok, err)
	}
	if payload, ok, err := flows.Take(ctx, "one", "social:google"); err != nil || !ok || string(payload) != "challenge" {
		t.Fatalf("take: %s %v %v", payload, ok, err)
	}
	if _, ok, err := flows.Take(ctx, "one", "social:google"); err != nil || ok {
		t.Fatalf("replayed flow: %v %v", ok, err)
	}
	if err := flows.Put(ctx, "expired", "social:google", []byte("old"), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := flows.Take(ctx, "expired", "social:google"); err != nil || ok {
		t.Fatalf("expired flow: %v %v", ok, err)
	}
}
