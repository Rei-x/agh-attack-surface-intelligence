package db

import (
	"context"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// The service-by-host index must follow upserts, deletes and a reload of the state.
func TestServiceIndexFollowsWritesAndReload(t *testing.T) {
	ctx := context.Background()
	m, vault := newRetentionStore(t)
	now := time.Now().UTC()
	a, _ := m.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.1", FirstSeen: now, LastSeen: now})
	b, _ := m.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.2", FirstSeen: now, LastSeen: now})
	for _, p := range []int{22, 80, 443} {
		if _, err := m.UpsertObservedService(ctx, &domain.Service{HostID: a.ID, Port: p, State: "open"}); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = m.UpsertObservedService(ctx, &domain.Service{HostID: b.ID, Port: 22, State: "open"})
	// Same host/port/protocol updates the existing row instead of adding one.
	s80, _ := m.UpsertObservedService(ctx, &domain.Service{HostID: a.ID, Port: 80, State: "closed"})

	raw, _, err := m.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewMemoryStore(vault) // same vault: the row DEKs must match
	if _, _, err := m2.ImportState(raw); err != nil {
		t.Fatal(err)
	}
	for _, st := range []*MemoryStore{m, m2} {
		ha, _ := st.GetHost(ctx, a.ID)
		if len(ha.Services) != 3 || ha.Services[1].Port != 80 || ha.Services[1].State != "closed" || ha.Services[1].ID != s80.ID {
			t.Fatalf("host a services: %+v", ha.Services)
		}
		if svcs, _ := st.ListServicesByHost(ctx, b.ID); len(svcs) != 1 || svcs[0].Port != 22 {
			t.Fatalf("host b services: %+v", svcs)
		}
	}
	if err := m2.DeleteHost(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ := m2.ListServices(ctx, ServiceFilter{}); len(all) != 1 {
		t.Fatalf("services after deleting host a: %d", len(all))
	}
	if svcs, _ := m2.ListServicesByHost(ctx, a.ID); len(svcs) != 0 {
		t.Fatalf("deleted host still has services: %+v", svcs)
	}
}
