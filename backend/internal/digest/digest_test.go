package digest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/remediation"
)

var now = time.Date(2026, 11, 21, 6, 30, 0, 0, time.UTC)

func fixture() Input {
	since := now.Add(-24 * time.Hour)
	at := now.Add(-2 * time.Hour)
	old := now.Add(-48 * time.Hour)
	hosts := []domain.Host{
		{ID: "h1", IP: "10.66.0.10", Owner: "wi-it@agh.edu.pl", LifecycleState: domain.HostStateActive, Services: []domain.Service{
			{ID: "s1", HostID: "h1", Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: "1.14.0", IsAdminPanel: true, Interestingness: 80},
			{ID: "s2", HostID: "h1", Port: 443, Protocol: "tcp", State: "open", ServiceName: "https", Interestingness: 20},
		}},
		{ID: "h2", IP: "10.70.1.5", LifecycleState: domain.HostStateActive, Services: []domain.Service{
			{ID: "s3", HostID: "h2", Port: 23, Protocol: "tcp", State: "open", ServiceName: "telnet", Interestingness: 70},
		}},
		{ID: "h3", IP: "10.70.1.9", LifecycleState: domain.HostStateInactive, Owner: "ftims@agh.edu.pl"},
		{ID: "h4", IP: "10.66.0.11", Owner: "wi-it@agh.edu.pl", LifecycleState: domain.HostStateActive, Services: []domain.Service{
			{ID: "s4", HostID: "h4", Port: 3306, Protocol: "tcp", State: "open", ServiceName: "mysql", Interestingness: 60,
				Triage: &domain.TriageInfo{Status: domain.TriageAcceptedRisk, Reason: "lab"}},
		}},
	}
	changes := []domain.ChangeEvent{
		{HostID: "h1", HostIP: "10.66.0.10", ServiceID: "s1", Port: 80, EventType: "ADMIN_PANEL_EXPOSED", Severity: "high", CreatedAt: at, After: map[string]any{"service": "http", "product": "nginx"}},
		{HostID: "h2", HostIP: "10.70.1.5", EventType: "NEW_HOST", CreatedAt: at},
		{HostID: "h2", HostIP: "10.70.1.5", ServiceID: "s3", Port: 23, EventType: "NEW_SERVICE", Severity: "high", CreatedAt: at, After: map[string]any{"service": "telnet"}},
		{HostID: "h3", HostIP: "10.70.1.9", EventType: "HOST_INACTIVE", CreatedAt: at, After: map[string]any{"owner": "ftims@agh.edu.pl"}},
		{HostID: "h1", HostIP: "10.66.0.10", ServiceID: "s9", Port: 8080, EventType: "SERVICE_CLOSED", CreatedAt: at, Before: map[string]any{"service": "http-proxy"}},
		{HostID: "h4", HostIP: "10.66.0.11", ServiceID: "s4", Port: 3306, EventType: "NEW_SERVICE", CreatedAt: at},
		// Outside the window: ignored.
		{HostID: "h1", HostIP: "10.66.0.10", EventType: "NEW_HOST", CreatedAt: old},
	}
	fixedAt := now.Add(-3 * time.Hour)
	pastDue := now.Add(-24 * time.Hour)
	tickets := []remediation.Ticket{
		{ID: "t1", HostID: "h1", HostIP: "10.66.0.10", Port: 21, Title: "FTP (cleartext login) open", Owner: "wi-it@agh.edu.pl", Status: remediation.StatusFixed, FixedAt: &fixedAt, Verified: true, LastCheckNote: "port 21/tcp is closed"},
		{ID: "t2", HostID: "h2", HostIP: "10.70.1.5", ServiceID: "s3", Port: 23, Kind: remediation.KindCleartextAdmin, Title: "Telnet open", Status: remediation.StatusNotified, DueAt: &pastDue},
		{ID: "t3", HostID: "h1", HostIP: "10.66.0.10", ServiceID: "s2", Port: 443, Kind: remediation.KindOther, Title: "Review", Status: remediation.StatusOpen},
	}
	return Input{Now: now, Since: since, Changes: changes, Hosts: hosts, Tickets: tickets}
}

func TestBuildDigest(t *testing.T) {
	d := Build(fixture())
	c := d.Counts
	if c.NewHosts != 1 || c.GoneHosts != 1 || c.NewServices != 3 || c.ClosedServices != 1 {
		t.Fatalf("counts: %+v", c)
	}
	if c.Fixed != 1 || c.Overdue != 1 || c.OpenTickets != 2 {
		t.Fatalf("remediation counts: %+v", c)
	}
	// Risky: nginx EOL + admin panel on h1, telnet on h2; accepted-risk mysql left out.
	kinds := map[string]bool{}
	for _, r := range d.Risky {
		kinds[r.Kind] = true
		if r.HostID == "h4" {
			t.Fatal("accepted risk must not be listed as risky")
		}
	}
	if !kinds[remediation.KindEOL] || !kinds[remediation.KindAdminPanel] || !kinds[remediation.KindCleartextAdmin] || len(d.Risky) != 3 {
		t.Fatalf("risky: %+v", d.Risky)
	}
	if d.Risky[0].Score < d.Risky[len(d.Risky)-1].Score {
		t.Fatal("risky must be sorted by score")
	}
	// Top risks: highest score first, at most 5, ticket status attached.
	if len(d.TopRisks) == 0 || d.TopRisks[0].ServiceID != "s1" || len(d.TopRisks) > 5 {
		t.Fatalf("top: %+v", d.TopRisks)
	}
	for _, r := range d.TopRisks {
		if r.ServiceID == "s3" && r.Ticket != remediation.StatusNotified {
			t.Fatalf("telnet top risk must show its ticket: %+v", r)
		}
	}
	// Owners: wi-it first (most weight), Unassigned last.
	if len(d.Owners) < 3 || d.Owners[0].Owner != "wi-it@agh.edu.pl" || d.Owners[len(d.Owners)-1].Owner != Unassigned {
		t.Fatalf("owners: %+v", d.Owners)
	}
	if !strings.Contains(d.Headline, "3 new risky exposures") || !strings.Contains(d.Headline, "1 fix verified") || !strings.Contains(d.Headline, "1 ticket overdue") {
		t.Fatalf("headline: %q", d.Headline)
	}
	md := d.Markdown()
	for _, want := range []string{"# Dzięcioł digest 2026-11-21", "## Top risks", "## Remediation", "Fixed: FTP (cleartext login) open", "### wi-it@agh.edu.pl", "### Unassigned"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown misses %q\n%s", want, md)
		}
	}
	if strings.ContainsAny(md, "\u2013\u2014") {
		t.Error("markdown must not contain dashes")
	}

	quiet := Build(Input{Now: now, Since: now.Add(-time.Hour)})
	if quiet.Headline != "Quiet night: nothing new on the network." || quiet.Risky == nil || quiet.Owners == nil {
		t.Fatalf("quiet digest: %+v", quiet)
	}
}

func TestDigestServiceSchedulesDelivery(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
	}))
	defer srv.Close()

	clock := time.Date(2026, 11, 21, 4, 0, 0, 0, time.UTC) // 05:00 Warsaw
	s := NewService(store, remediation.NewRepo(store), outbound.NewDeliverer(store, nil))
	s.Now = func() time.Time { return clock }
	if _, err := s.SaveSettings(ctx, &Settings{Enabled: true, SendAt: "07:00", Timezone: "Europe/Warsaw", OnlyScheduled: true, WebhookURL: srv.URL + "/digest"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSettings(ctx, &Settings{SendAt: "7am"}, false); err == nil {
		t.Fatal("bad time must be refused")
	}

	// A manual run does not build a digest.
	s.OnScanCompleted(ctx, &domain.ScanRun{ID: "r0", Status: domain.ScanStatusCompleted, TriggeredBy: "ana"})
	if ds, _ := s.List(ctx); len(ds) != 0 {
		t.Fatalf("manual run must not build a digest: %d", len(ds))
	}
	// The nightly scheduled run finishes at 05:00: digest built, not sent yet.
	s.OnScanCompleted(ctx, &domain.ScanRun{ID: "r1", Name: "nightly", Status: domain.ScanStatusCompleted, TriggeredBy: TriggeredByScheduler})
	ds, _ := s.List(ctx)
	if len(ds) != 1 || ds[0].ScanRunID != "r1" || ds[0].Delivered || len(got) != 0 {
		t.Fatalf("digest should wait for 07:00: %+v, sent %d", ds, len(got))
	}
	// 07:01 Warsaw: delivered once.
	clock = time.Date(2026, 11, 21, 6, 1, 0, 0, time.UTC)
	s.Tick(ctx)
	s.Tick(ctx)
	ds, _ = s.List(ctx)
	if len(got) != 1 || !ds[0].Delivered || !strings.Contains(got[0], "Dzięcioł digest 2026-11-21") {
		t.Fatalf("expected one delivery: %v %+v", got, ds[0])
	}
	// The public view hides the webhook.
	pub := s.LoadSettings(ctx).Public()
	if pub.WebhookURL != "" || !pub.HasWebhookURL || pub.LastDeliveredDay != "2026-11-21" {
		t.Fatalf("public settings: %+v", pub)
	}
}
