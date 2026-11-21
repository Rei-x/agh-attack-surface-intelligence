package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestPostgresServiceProductSourceRoundTrip(t *testing.T) {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set ASI_TEST_DATABASE_URL to run against PostgreSQL")
	}
	ctx := context.Background()
	vault, err := crypto.NewVault(os.Getenv("ASI_MASTER_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(ctx, url, vault)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	now := time.Now().UTC()
	h, err := s.UpsertObservedHost(ctx, &domain.Host{IP: "10.250.0.7", LifecycleState: domain.HostStateNew, FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.UpsertObservedService(ctx, &domain.Service{HostID: h.ID, Port: 8080, Protocol: "tcp", State: "open",
		ServiceName: "http", Product: "Apache Tomcat", Version: "9.0.83", ProductSource: "http-page", VersionSource: "http-page",
		TriageStatus: "new", FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	if saved.ProductSource != "http-page" || saved.VersionSource != "http-page" {
		t.Fatalf("GetService lost sources: %+v", saved)
	}
	list, err := s.ListServices(ctx, ServiceFilter{HostID: h.ID})
	if err != nil || len(list) != 1 || list[0].ProductSource != "http-page" {
		t.Fatalf("ListServices: %v %+v", err, list)
	}
}
