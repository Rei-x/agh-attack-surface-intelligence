package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type captureNotifier struct{ got []domain.ChangeEvent }

func (c *captureNotifier) NotifyChanges(_ context.Context, _ *domain.ScanRun, ch []domain.ChangeEvent) {
	c.got = append(c.got, ch...)
}

func TestCIDRTagRulesAppliedOnIngestAndRiskyExposureAlerted(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	rules := []domain.TagRule{
		{CIDR: "10.66.0.0/22", Tags: []string{"wydzial-wi"}, Owner: "admin@wi.agh.edu.pl", Enabled: true},
		{CIDR: "10.66.1.0/24", Tags: []string{"lab"}, Owner: "lab@wi.agh.edu.pl", Environment: "dev", Enabled: true},
		{CIDR: "10.66.0.0/16", Tags: []string{"disabled-rule"}, Enabled: false},
	}
	for i := range rules {
		if err := NormalizeTagRule(&rules[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SaveSetting(ctx, db.SettingTagRules, rules); err != nil {
		t.Fatal(err)
	}
	notifier := &captureNotifier{}
	p := NewPipeline(store, NewDefaultAnalyzer(), nil)
	p.SetNotifier(notifier)

	_, err := p.ProcessObservations(ctx, IngestRequest{
		RunType: domain.ScanTypeManual,
		Observations: []domain.ObservedHost{
			{IP: "10.66.1.20", IsAlive: true, Services: []domain.ObservedService{{Port: 22, ServiceName: "ssh"}}},
			{IP: "10.66.2.7", IsAlive: true, Tags: []string{"manual"}, Services: []domain.ObservedService{{Port: 80, ServiceName: "http"}}},
			{IP: "10.99.0.1", IsAlive: true, Services: []domain.ObservedService{{Port: 80, ServiceName: "http"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	lab, _ := store.GetHostByIP(ctx, "10.66.1.20")
	if !hasAll(lab.Tags, "wydzial-wi", "lab") || lab.Owner != "lab@wi.agh.edu.pl" || lab.Environment != "dev" {
		t.Fatalf("most specific rule should win owner/env, tags union: %+v owner=%s env=%s", lab.Tags, lab.Owner, lab.Environment)
	}
	wi, _ := store.GetHostByIP(ctx, "10.66.2.7")
	if !hasAll(wi.Tags, "wydzial-wi", "manual") || wi.Owner != "admin@wi.agh.edu.pl" || hasAll(wi.Tags, "disabled-rule") {
		t.Fatalf("wi host: tags=%v owner=%s", wi.Tags, wi.Owner)
	}
	other, _ := store.GetHostByIP(ctx, "10.99.0.1")
	if len(other.Tags) != 0 || other.Owner != "" {
		t.Fatalf("host outside rules must stay untouched: %+v", other)
	}

	// Analyst override of owner wins over the rule and survives the next scan.
	if err := store.PatchOverrides(ctx, "host", wi.ID, map[string]any{"owner": "soc@agh.edu.pl"}, nil, "analyst"); err != nil {
		t.Fatal(err)
	}
	notifier.got = nil
	_, err = p.ProcessObservations(ctx, IngestRequest{
		RunType: domain.ScanTypeManual,
		Observations: []domain.ObservedHost{
			{IP: "10.66.2.7", IsAlive: true, Services: []domain.ObservedService{
				{Port: 80, ServiceName: "http"},
				{Port: 3389, ServiceName: "ms-wbt-server"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wi, _ = store.GetHostByIP(ctx, "10.66.2.7")
	if wi.Owner != "soc@agh.edu.pl" || wi.ScannerObserved["owner"] != "admin@wi.agh.edu.pl" {
		t.Fatalf("override must win, rule value visible as scanner-observed: owner=%s observed=%v", wi.Owner, wi.ScannerObserved)
	}

	var rdp *domain.ChangeEvent
	for i := range notifier.got {
		if notifier.got[i].Port == 3389 {
			rdp = &notifier.got[i]
		}
	}
	if rdp == nil || rdp.Severity != "high" || rdp.EventType != "NEW_SERVICE" {
		t.Fatalf("new RDP exposure should be a high-severity change passed to the notifier: %+v", notifier.got)
	}
}

func TestPipelineDoesNotLeakTriageOverrideIntoObservedRow(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	p := NewPipeline(store, NewDefaultAnalyzer(), nil)
	obs := []domain.ObservedHost{{IP: "10.0.0.9", IsAlive: true, Services: []domain.ObservedService{{Port: 445, ServiceName: "microsoft-ds"}}}}
	if _, err := p.ProcessObservations(ctx, IngestRequest{Observations: obs}); err != nil {
		t.Fatal(err)
	}
	h, _ := store.GetHostByIP(ctx, "10.0.0.9")
	svcID := h.Services[0].ID
	exp := time.Now().Add(time.Hour)
	_ = store.PatchOverrides(ctx, "service", svcID, map[string]any{"triage": domain.TriageInfo{
		Status: domain.TriageAcceptedRisk, Reason: "file server", ExpiresAt: &exp,
	}}, nil, "analyst")
	// Re-scan while accepted, then remove the decision: the finding must be "new" again,
	// not stuck as accepted_risk copied into the observed record.
	if _, err := p.ProcessObservations(ctx, IngestRequest{Observations: obs}); err != nil {
		t.Fatal(err)
	}
	svc, _ := store.GetService(ctx, svcID)
	if svc.TriageStatus != domain.TriageAcceptedRisk {
		t.Fatalf("acceptance lost across scan: %s", svc.TriageStatus)
	}
	_ = store.PatchOverrides(ctx, "service", svcID, nil, []string{"triage"}, "analyst")
	svc, _ = store.GetService(ctx, svcID)
	if svc.TriageStatus != domain.TriageNew {
		t.Fatalf("after unlocking, observed triage must be new, got %s", svc.TriageStatus)
	}
}

func hasAll(list []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, l := range list {
			if l == w {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
