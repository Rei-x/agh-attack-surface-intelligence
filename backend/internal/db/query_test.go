package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestParseAssetQuery(t *testing.T) {
	q, err := ParseAssetQuery(`port:3389,445 tech:WordPress tag:wi state:new cidr:10.66.0.0/24 env:staging title:"admin panel" cert:expired -env:prod portal`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(q.Terms) != 9 {
		t.Fatalf("want 9 terms, got %d: %+v", len(q.Terms), q.Terms)
	}
	if got := q.Terms[0]; got.Key != "port" || len(got.ports) != 2 || got.ports[1] != 445 {
		t.Fatalf("port term: %+v", got)
	}
	if got := q.Terms[1]; got.Values[0] != "wordpress" {
		t.Fatalf("tech value should be lower-cased: %+v", got)
	}
	if got := q.Terms[6]; got.Key != "title" || got.Values[0] != "admin panel" {
		t.Fatalf("quoted title: %+v", got)
	}
	if got := q.Terms[8]; got.Key != "env" || !got.Negate {
		t.Fatalf("negated env: %+v", got)
	}
	if len(q.Text) != 1 || q.Text[0] != "portal" {
		t.Fatalf("free text: %+v", q.Text)
	}

	// Unknown keys and host:port stay free text; a bare IP is free text too.
	q, err = ParseAssetQuery(`http://intranet 10.0.0.1:8080 10.0.0.1`)
	if err != nil || len(q.Terms) != 0 || len(q.Text) != 3 {
		t.Fatalf("free text fallback: %+v err=%v", q, err)
	}

	for _, bad := range []string{`port:abc`, `port:70000`, `cidr:10.0.0.0/99`, `cert:weird`, `title:"open`, `port:`, `score:x`} {
		if _, err := ParseAssetQuery(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func queryHosts() []domain.Host {
	now := time.Now()
	return []domain.Host{
		{
			ID: "h1", IP: "10.66.0.15", Hostname: "wi-portal.agh.edu.pl", LifecycleState: "NEW", Environment: "staging",
			Tags: []string{"wi"}, Owner: "admin@wi.agh.edu.pl",
			Services: []domain.Service{
				{ID: "s1", Port: 443, ServiceName: "https", Technologies: []domain.DetectedTechnology{{Name: "WordPress"}},
					HTTP: &domain.HTTPFingerprint{Title: "WI Admin Panel", TLS: &domain.TLSInfo{IsExpired: true, NotAfter: now.Add(-time.Hour)}}},
				{ID: "s2", Port: 3389, ServiceName: "ms-wbt-server"},
			},
		},
		{
			ID: "h2", IP: "10.70.1.1", LifecycleState: "ACTIVE", Environment: "prod",
			Services: []domain.Service{
				{ID: "s3", Port: 3389, ServiceName: "ms-wbt-server"},
				{ID: "s4", Port: 80, Technologies: []domain.DetectedTechnology{{Name: "WordPress"}}},
			},
		},
	}
}

func matchIDs(t *testing.T, query string) []string {
	t.Helper()
	q, err := ParseAssetQuery(query)
	if err != nil {
		t.Fatalf("parse %q: %v", query, err)
	}
	var out []string
	for _, h := range queryHosts() {
		h := h
		if q.MatchHost(&h) {
			out = append(out, h.ID)
		}
	}
	return out
}

func TestAssetQueryMatchHost(t *testing.T) {
	cases := map[string][]string{
		"port:3389":                           {"h1", "h2"},
		"port:3389 state:new":                 {"h1"},
		"cidr:10.66.0.0/22":                   {"h1"},
		"cidr:10.70.1.1":                      {"h2"},
		"tech:wordpress":                      {"h1", "h2"},
		`title:"admin panel"`:                 {"h1"},
		"cert:expired":                        {"h1"},
		"env:staging tag:wi":                  {"h1"},
		"-env:prod":                           {"h1"},
		"owner:wi.agh":                        {"h1"},
		"wi-portal":                           {"h1"},
		"tech:wordpress port:443":             {"h1"}, // same-service semantics
		"tech:wordpress port:80":              {"h2"},
		"tech:wordpress port:3389":            nil, // no single service has both
		"state:new,active port:3389 ms-wbt":   {"h1", "h2"},
		"hostname:wi-portal cert:expired 443": {"h1"},
	}
	for q, want := range cases {
		got := matchIDs(t, q)
		if len(got) != len(want) {
			t.Errorf("%q: got %v want %v", q, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q: got %v want %v", q, got, want)
			}
		}
	}
}

func TestListHostsAndServicesWithQueryLanguage(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := NewMemoryStore(vault)
	for _, h := range queryHosts() {
		svcs := h.Services
		h.Services = nil
		saved, err := store.UpsertObservedHost(ctx, &h)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range svcs {
			s.HostID = saved.ID
			s.State = "open"
			if _, err := store.UpsertObservedService(ctx, &s); err != nil {
				t.Fatal(err)
			}
		}
	}
	hosts, total, err := store.ListHosts(ctx, HostFilter{Query: "port:3389 cidr:10.66.0.0/16"})
	if err != nil || total != 1 || hosts[0].IP != "10.66.0.15" {
		t.Fatalf("ListHosts query: total=%d err=%v", total, err)
	}
	svcs, err := store.ListServices(ctx, ServiceFilter{Query: "port:3389 cidr:10.70.0.0/16"})
	if err != nil || len(svcs) != 1 || svcs[0].HostIP != "10.70.1.1" {
		t.Fatalf("ListServices query: %+v err=%v", svcs, err)
	}
}

func TestTriageOverrideExpiryAndPersistence(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := NewMemoryStore(vault)
	h, _ := store.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.5", LifecycleState: "ACTIVE"})
	svc, _ := store.UpsertObservedService(ctx, &domain.Service{HostID: h.ID, Port: 3389, State: "open", TriageStatus: "new"})

	future := time.Now().Add(48 * time.Hour)
	if err := store.PatchOverrides(ctx, "service", svc.ID, map[string]any{"triage": domain.TriageInfo{
		Status: domain.TriageAcceptedRisk, Reason: "jump host behind VPN", By: "analyst", At: time.Now(), ExpiresAt: &future,
	}}, nil, "analyst"); err != nil {
		t.Fatal(err)
	}
	got, _ := store.GetService(ctx, svc.ID)
	if got.TriageStatus != domain.TriageAcceptedRisk || got.Triage == nil || got.Triage.Expired || !got.Triage.IsSuppressing(time.Now()) {
		t.Fatalf("active acceptance not applied: %+v %+v", got.TriageStatus, got.Triage)
	}
	if got.Triage.Reason != "jump host behind VPN" || got.Triage.By != "analyst" {
		t.Fatalf("triage metadata lost: %+v", got.Triage)
	}

	// The decision is preserved across a re-scan of the same service (observed upsert).
	svc.Banner = "changed"
	if _, err := store.UpsertObservedService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if got, _ = store.GetService(ctx, svc.ID); got.TriageStatus != domain.TriageAcceptedRisk {
		t.Fatalf("acceptance lost after re-scan: %s", got.TriageStatus)
	}

	// Expiry: evaluated on read; an expired acceptance reverts to an active finding.
	past := time.Now().Add(-time.Minute)
	expired := decodeTriageAt(map[string]any{"status": "accepted_risk", "reason": "x", "expires_at": past.Format(time.RFC3339Nano)}, time.Now())
	if expired == nil || !expired.Expired || expired.IsSuppressing(time.Now()) {
		t.Fatalf("expected expired triage, got %+v", expired)
	}
	if err := store.PatchOverrides(ctx, "service", svc.ID, map[string]any{"triage": domain.TriageInfo{
		Status: domain.TriageAcceptedRisk, Reason: "temporary", ExpiresAt: &past,
	}}, nil, "analyst"); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetService(ctx, svc.ID)
	if got.TriageStatus != domain.TriageNew || got.Triage == nil || !got.Triage.Expired {
		t.Fatalf("expired acceptance should revert to new: status=%s triage=%+v", got.TriageStatus, got.Triage)
	}

	// Host-level decision.
	if err := store.PatchOverrides(ctx, "host", h.ID, map[string]any{"triage": domain.TriageInfo{
		Status: domain.TriageFalsePositive, Reason: "honeypot", At: time.Now(),
	}}, nil, "analyst"); err != nil {
		t.Fatal(err)
	}
	gh, _ := store.GetHost(ctx, h.ID)
	if gh.TriageStatus != domain.TriageFalsePositive || !gh.Triage.IsSuppressing(time.Now()) {
		t.Fatalf("host triage: %+v", gh.Triage)
	}
}

func TestSettingsEncryptedAndInSnapshot(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := NewMemoryStore(vault)
	secret := map[string]any{"url": "https://hooks.slack.com/services/T000/B000/SECRET"}
	if err := store.SaveSetting(ctx, SettingWebhook, secret); err != nil {
		t.Fatal(err)
	}
	raw, _, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Fatal("webhook secret must be encrypted inside the snapshot")
	}
	restored := NewMemoryStore(vault)
	if _, _, err := restored.ImportState(raw); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	found, err := restored.GetSetting(ctx, SettingWebhook, &got)
	if err != nil || !found || got["url"] != secret["url"] {
		t.Fatalf("setting not restored from snapshot: found=%v err=%v got=%v", found, err, got)
	}
	// Key rotation re-encrypts settings too.
	if _, err := restored.ReEncryptAll(ctx); err != nil {
		t.Fatal(err)
	}
	if found, err := restored.GetSetting(ctx, SettingWebhook, &got); err != nil || !found {
		t.Fatalf("setting unreadable after re-encryption: %v", err)
	}
}
