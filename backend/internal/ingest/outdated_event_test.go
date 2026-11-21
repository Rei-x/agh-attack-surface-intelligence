package ingest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestOutdatedVersionEventScoreAndOwner(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	rules := []domain.TagRule{{CIDR: "10.66.0.0/24", Owner: "admin@wi.agh.edu.pl", Tags: []string{"wi"}, Enabled: true}}
	_ = NormalizeTagRule(&rules[0])
	if err := store.SaveSetting(ctx, db.SettingTagRules, rules); err != nil {
		t.Fatal(err)
	}
	p := NewPipeline(store, NewDefaultAnalyzer(), nil)
	obs := func(version string) []domain.ObservedHost {
		return []domain.ObservedHost{{IP: "10.66.0.12", IsAlive: true, ObservedAt: time.Now(), Services: []domain.ObservedService{{
			Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: version,
			HTTP: &domain.HTTPFingerprint{ServerHeader: "nginx/" + version},
		}}}}
	}
	eventsOf := func(res *IngestResult, typ string) []domain.ChangeEvent {
		var out []domain.ChangeEvent
		for _, ev := range res.Changes {
			if ev.EventType == typ {
				out = append(out, ev)
			}
		}
		return out
	}

	res, err := p.ProcessObservations(ctx, IngestRequest{RunType: domain.ScanTypeManual, Observations: obs("1.14.2")})
	if err != nil {
		t.Fatal(err)
	}
	ev := eventsOf(res, EventOutdatedVersion)
	if len(ev) != 1 || !strings.Contains(ev[0].Summary, "nginx 1.14 – gałąź EOL od 2019-04") || ev[0].After["owner"] != "admin@wi.agh.edu.pl" {
		t.Fatalf("OUTDATED_VERSION event: %+v", ev)
	}
	for _, e := range res.Changes {
		if e.After["owner"] != "admin@wi.agh.edu.pl" {
			t.Fatalf("every change event must carry the CIDR owner: %+v", e)
		}
	}
	svcs, _ := store.ListServices(ctx, db.ServiceFilter{})
	if len(svcs) != 1 || svcs[0].Interestingness < 15 || !hasTagFold(svcs[0].Tags, "eol") {
		t.Fatalf("EOL must raise score and tag the service: %+v", svcs)
	}
	found := false
	for _, f := range svcs[0].InterestingFactors {
		found = found || strings.HasPrefix(f.Reason, "Wersja EOL: nginx 1.14")
	}
	if !found {
		t.Fatalf("EOL factor missing: %+v", svcs[0].InterestingFactors)
	}

	// Same version again: no repeated event. Upgrade to another EOL branch: new event.
	res, _ = p.ProcessObservations(ctx, IngestRequest{RunType: domain.ScanTypeManual, Observations: obs("1.14.2")})
	if n := len(eventsOf(res, EventOutdatedVersion)); n != 0 {
		t.Fatalf("unchanged EOL service must stay quiet, got %d events", n)
	}
	res, _ = p.ProcessObservations(ctx, IngestRequest{RunType: domain.ScanTypeManual, Observations: obs("1.20.1")})
	if ev := eventsOf(res, EventOutdatedVersion); len(ev) != 1 || !strings.Contains(ev[0].Summary, "1.20") {
		t.Fatalf("version change into another EOL branch must alert: %+v", ev)
	}
	// Upgrade to a supported branch: no event, tag gone.
	res, _ = p.ProcessObservations(ctx, IngestRequest{RunType: domain.ScanTypeManual, Observations: obs("1.30.1")})
	if n := len(eventsOf(res, EventOutdatedVersion)); n != 0 {
		t.Fatal("supported version must not alert")
	}
	svcs, _ = store.ListServices(ctx, db.ServiceFilter{})
	if hasTagFold(svcs[0].Tags, "eol") {
		t.Fatalf("eol tag must be dropped after upgrade: %v", svcs[0].Tags)
	}
}
