package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestServiceOptInScopeAndAnnotation(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	port, _ := tcpServer(t, lineServer(func(string) string { return "# Server\r\nredis_version:6.0.9\r\n" }))

	p := &domain.ScanProfile{Name: "lab", Targets: []string{"127.0.0.1/32"}, HTTPRPS: 10, Enabled: true}
	if err := store.CreateProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var svcIDs []string
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		h, err := store.UpsertObservedHost(ctx, &domain.Host{IP: ip, LifecycleState: domain.HostStateActive, FirstSeen: now, LastSeen: now})
		if err != nil {
			t.Fatal(err)
		}
		s, err := store.UpsertObservedService(ctx, &domain.Service{HostID: h.ID, HostIP: ip, Port: port, Protocol: "tcp", State: "open", ServiceName: "redis", FirstSeen: now, LastSeen: now})
		if err != nil {
			t.Fatal(err)
		}
		svcIDs = append(svcIDs, s.ID)
	}

	svc, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	svc.Timeout = 2 * time.Second
	var audits []domain.AuditLog
	svc.Audit = func(_ context.Context, a *domain.AuditLog) { audits = append(audits, *a) }
	recorded := 0
	svc.OnRecorded = func() { recorded++ }

	// Off by default.
	if _, err := svc.RunProfile(ctx, p.ID, "", "", "manual"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
	if svc.Results.Profile(p.ID).Enabled {
		t.Fatal("verification must be off by default")
	}
	// Default creds cannot be on without Verify.
	_ = svc.Results.SetProfile(ctx, p.ID, ProfileConfig{Enabled: false, DefaultCreds: true})
	if svc.Results.Profile(p.ID).DefaultCreds {
		t.Fatal("default creds enabled without verify")
	}

	if err := svc.Results.SetProfile(ctx, p.ID, ProfileConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sum, err := svc.RunProfile(ctx, p.ID, "", "run-1", "manual")
	if err != nil {
		t.Fatal(err)
	}
	// Only the in-scope host (127.0.0.1) was a target.
	if sum.Stats.Targets != 1 || sum.Stats.Findings != 1 || sum.BySeverity["high"] != 1 || recorded != 1 {
		t.Fatalf("summary: %+v", sum)
	}
	if len(audits) == 0 || audits[len(audits)-1].Action != "verify.run" {
		t.Fatalf("audit: %+v", audits)
	}

	// Read-time annotation and score factor.
	s := domain.Service{ID: svcIDs[0]}
	f := svc.Annotator(&s, now)
	if len(s.Verified) != 1 || s.Verified[0].CheckID != "redis-unauth" || len(f) != 1 || f[0].Points != verifiedPoints["high"] || !strings.HasPrefix(f[0].Reason, FactorVerified) {
		t.Fatalf("annotation: %+v %+v", s.Verified, f)
	}
	other := domain.Service{ID: svcIDs[1]}
	if svc.Annotator(&other, now); other.Verified != nil {
		t.Fatal("out-of-scope service got findings")
	}

	// Results survive a restart (persisted through the settings store).
	again, _ := NewService(store)
	if got := again.Results.ForService(svcIDs[0]); len(got) != 1 || !again.Results.Profile(p.ID).Enabled {
		t.Fatalf("not persisted: %+v", got)
	}
	if last, ok := again.Results.LastRun(p.ID); !ok || last.ScanRunID != "run-1" {
		t.Fatalf("last run: %+v", last)
	}
}
