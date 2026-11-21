package remediation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/notify"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/outbound"
)

var t0 = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func TestStatusTransitions(t *testing.T) {
	cases := []struct {
		from, to string
		ok       bool
	}{
		{StatusOpen, StatusNotified, true},
		{StatusOpen, StatusFixed, true},
		{StatusOpen, StatusReopened, false},
		{StatusNotified, StatusNotified, true},
		{StatusNotified, StatusAcknowledged, true},
		{StatusAcknowledged, StatusOpen, false},
		{StatusAcknowledged, StatusFixed, true},
		{StatusFixed, StatusNotified, false},
		{StatusFixed, StatusReopened, true},
		{StatusAcceptedRisk, StatusFixed, false},
		{StatusAcceptedRisk, StatusReopened, true},
		{StatusReopened, StatusAcceptedRisk, true},
	}
	for _, c := range cases {
		if got := CanTransition(c.from, c.to); got != c.ok {
			t.Errorf("%s -> %s: got %v want %v", c.from, c.to, got, c.ok)
		}
	}

	tk := &Ticket{Status: StatusOpen}
	if err := tk.SetStatus(StatusNotified, "ana", "sent", "", t0); err != nil {
		t.Fatal(err)
	}
	if tk.NotifiedAt == nil || !tk.NotifiedAt.Equal(t0) {
		t.Fatalf("notified_at not stamped: %+v", tk.NotifiedAt)
	}
	if err := tk.SetStatus(StatusOpen, "ana", "", "", t0); err == nil {
		t.Fatal("notified -> open must be refused")
	}
	if err := tk.SetStatus("bogus", "ana", "", "", t0); err == nil {
		t.Fatal("unknown status must be refused")
	}
	if err := tk.SetStatus(StatusFixed, SystemUser, "port closed", "scan-1", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !tk.Verified || tk.FixedScanID != "scan-1" || tk.FixedAt == nil {
		t.Fatalf("verified fix not recorded: %+v", tk)
	}
	if err := tk.SetStatus(StatusReopened, "ana", "back", "", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if tk.Verified || tk.FixedAt != nil || tk.FixedScanID != "" {
		t.Fatalf("reopen must clear the fix: %+v", tk)
	}
	if len(tk.History) != 3 || tk.History[1].Action != "verified_fixed" || tk.History[2].Action != "reopened" {
		t.Fatalf("history: %+v", tk.History)
	}
}

func eolHost(version string, state string) *domain.Host {
	return &domain.Host{
		ID: "h1", IP: "10.0.0.5", LifecycleState: domain.HostStateActive,
		Services: []domain.Service{{
			ID: "s1", HostID: "h1", HostIP: "10.0.0.5", Port: 80, Protocol: "tcp", State: state,
			ServiceName: "http", Product: "nginx", Version: version,
		}},
	}
}

func eolTicket() Ticket {
	due := t0.Add(48 * time.Hour)
	return Ticket{ID: "t1", HostID: "h1", HostIP: "10.0.0.5", ServiceID: "s1", Port: 80, Protocol: "tcp",
		Kind: KindEOL, IssueKey: "eol:nginx:1.14", Status: StatusNotified, DueAt: &due, CreatedAt: t0}
}

func TestCheckDetectsEachKindOfFix(t *testing.T) {
	tk := eolTicket()
	if r := Check(&tk, eolHost("1.14.0", "open"), t0); !r.Known || !r.Present {
		t.Fatalf("old nginx must still be present: %+v", r)
	}
	if r := Check(&tk, eolHost("1.30.1", "open"), t0); !r.Known || r.Present || !strings.Contains(r.Reason, "no longer end of life") {
		t.Fatalf("upgraded nginx must count as fixed: %+v", r)
	}
	if r := Check(&tk, eolHost("1.14.0", "closed"), t0); r.Present || !strings.Contains(r.Reason, "closed") {
		t.Fatalf("closed port must count as fixed: %+v", r)
	}
	if r := Check(&tk, nil, t0); r.Present || !r.Known {
		t.Fatalf("deleted host must count as fixed: %+v", r)
	}
	missing := eolHost("1.14.0", "open")
	missing.LifecycleState = domain.HostStateMissing
	if r := Check(&tk, missing, t0); r.Known {
		t.Fatalf("missing host is not proof of a fix: %+v", r)
	}

	admin := &Ticket{HostID: "h1", ServiceID: "s1", Port: 80, Kind: KindAdminPanel, IssueKey: KindAdminPanel}
	h := eolHost("1.30.1", "open")
	h.Services[0].IsAdminPanel = true
	if r := Check(admin, h, t0); !r.Present {
		t.Fatalf("exposed panel must be present: %+v", r)
	}
	h.Services[0].IsAdminPanel = false
	if r := Check(admin, h, t0); r.Present {
		t.Fatalf("removed panel must count as fixed: %+v", r)
	}

	// Service ids can change when a host is re-created; the port still matches.
	byPort := &Ticket{HostID: "h1", ServiceID: "gone-id", Port: 80, Protocol: "tcp", Kind: KindExposure}
	if r := Check(byPort, eolHost("1.14.0", "open"), t0); !r.Present {
		t.Fatalf("port fallback must find the service: %+v", r)
	}
}

func TestVerifyFixesOverduesAndReopens(t *testing.T) {
	hosts := map[string]*domain.Host{"h1": eolHost("1.14.0", "open")}
	lookup := func(id string) (*domain.Host, bool) { return hosts[id], true }

	ts := []Ticket{eolTicket()}
	accepted := eolTicket()
	accepted.ID, accepted.Status = "t2", StatusAcceptedRisk
	ts = append(ts, accepted)

	// Before the due date nothing happens.
	if out := Verify(ts, lookup, "scan-1", t0.Add(time.Hour)); len(out) != 0 {
		t.Fatalf("expected no outcome, got %+v", out)
	}
	if ts[0].LastCheckScan != "scan-1" {
		t.Fatalf("last check not recorded: %+v", ts[0])
	}
	// Past due and still there: overdue once.
	out := Verify(ts, lookup, "scan-2", t0.Add(72*time.Hour))
	if len(out) != 1 || out[0].Action != "overdue" || !ts[0].Overdue {
		t.Fatalf("expected overdue: %+v / %+v", out, ts[0])
	}
	if out := Verify(ts, lookup, "scan-3", t0.Add(73*time.Hour)); len(out) != 0 {
		t.Fatalf("overdue must be flagged only once: %+v", out)
	}
	// Owner upgrades nginx: verified fixed with the scan as evidence.
	hosts["h1"] = eolHost("1.30.1", "open")
	out = Verify(ts, lookup, "scan-4", t0.Add(96*time.Hour))
	if len(out) != 1 || out[0].Action != "verified_fixed" {
		t.Fatalf("expected verified fix: %+v", out)
	}
	if ts[0].Status != StatusFixed || ts[0].FixedScanID != "scan-4" || !ts[0].Verified || ts[0].Overdue {
		t.Fatalf("ticket not fixed: %+v", ts[0])
	}
	if ts[1].Status != StatusAcceptedRisk {
		t.Fatal("accepted risk must be left alone")
	}
	// Someone rolls the old version back: the verified fix is reopened.
	hosts["h1"] = eolHost("1.14.0", "open")
	out = Verify(ts, lookup, "scan-5", t0.Add(120*time.Hour))
	if len(out) != 1 || out[0].Action != "reopened" || ts[0].Status != StatusReopened {
		t.Fatalf("expected reopen: %+v / %s", out, ts[0].Status)
	}
	// Unreadable host record: leave the ticket alone.
	failing := func(string) (*domain.Host, bool) { return nil, false }
	if out := Verify(ts, failing, "scan-6", t0.Add(121*time.Hour)); len(out) != 0 || ts[0].Status != StatusReopened {
		t.Fatalf("lookup failure must not change tickets: %+v", out)
	}
}

func TestServiceIssuesAndDraft(t *testing.T) {
	svc := &domain.Service{HostIP: "10.0.0.9", Port: 23, Protocol: "tcp", ServiceName: "telnet"}
	is := ServiceIssues(svc, t0)
	if len(is) == 0 || is[0].Kind != KindCleartextAdmin || is[0].Action != ActionRemove {
		t.Fatalf("telnet must be a cleartext admin issue: %+v", is)
	}
	svc = &domain.Service{HostIP: "10.0.0.9", Port: 80, Protocol: "tcp", ServiceName: "http", Product: "nginx", Version: "1.14.0", IsAdminPanel: true}
	is = ServiceIssues(svc, t0)
	kinds := []string{}
	for _, i := range is {
		kinds = append(kinds, i.Kind)
	}
	if strings.Join(kinds, ",") != "eol,admin-panel" {
		t.Fatalf("kinds: %v", kinds)
	}
	due := t0.AddDate(0, 0, 30)
	tk := &Ticket{HostIP: "10.0.0.9", Port: 80, Protocol: "tcp", Title: is[0].Title, Evidence: is[0].Evidence, Action: ActionPatch, Owner: "WI IT <it@wi.agh.edu.pl>", DueAt: &due}
	d := BuildDraft(tk, is[0].Advice, t0)
	for _, want := range []string{"Hello WI IT,", "Where: 10.0.0.9:80/tcp", "What to do: Upgrade", "Please patch it by " + due.Format("2006-01-02")} {
		if !strings.Contains(d.Body, want) {
			t.Errorf("draft body misses %q:\n%s", want, d.Body)
		}
	}
	if strings.ContainsAny(d.Body+d.Subject, "\u2013\u2014") {
		t.Error("draft must not contain dashes")
	}
	if got := ExtractEmail("WI IT <it@wi.agh.edu.pl>"); got != "it@wi.agh.edu.pl" {
		t.Fatalf("email: %q", got)
	}
}

type hook struct {
	mu     sync.Mutex
	bodies []map[string]any
}

func (h *hook) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	h.mu.Lock()
	h.bodies = append(h.bodies, m)
	h.mu.Unlock()
}

func TestServiceNotifyFallbacksAndVerification(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	host, err := store.UpsertObservedHost(ctx, &domain.Host{IP: "10.66.0.7", LifecycleState: domain.HostStateActive, Owner: "wi-it@agh.edu.pl"})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := store.UpsertObservedService(ctx, &domain.Service{HostID: host.ID, Port: 23, Protocol: "tcp", State: "open", ServiceName: "telnet"})
	if err != nil {
		t.Fatal(err)
	}
	var audits []string
	s := NewService(store, outbound.NewDeliverer(store, nil))
	s.Audit = func(_ context.Context, e *domain.AuditLog) { audits = append(audits, e.Action) }
	var fixed []string
	s.OnVerifiedFix = func(_ context.Context, tk Ticket, scanID string) { fixed = append(fixed, tk.ID+"@"+scanID) }

	// Nothing configured: the draft says so and sending falls back to manual.
	d, err := s.Draft(ctx, host.ID, svc.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.OwnerEmail != "wi-it@agh.edu.pl" || d.IssueKey != "cleartext-admin:telnet" || d.Channels.Email || d.Channels.Webhook {
		t.Fatalf("draft: %+v", d)
	}
	res, err := s.Create(ctx, CreateRequest{HostID: host.ID, ServiceID: svc.ID, IssueKey: d.IssueKey, Subject: d.Subject, Body: d.Body}, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Delivery.Delivered || res.Delivery.Channel != outbound.ChannelManual || !strings.HasPrefix(res.Delivery.Mailto, "mailto:wi-it@agh.edu.pl?") {
		t.Fatalf("manual fallback expected: %+v", res.Delivery)
	}
	if res.Ticket.Status != StatusOpen {
		t.Fatalf("undelivered ticket must stay open: %s", res.Ticket.Status)
	}

	// Alert webhook configured: the next send goes there (Teams format) and the same
	// ticket is reused.
	h := &hook{}
	srv := httptest.NewServer(http.HandlerFunc(h.handler))
	defer srv.Close()
	if err := notify.SaveConfig(ctx, store, &domain.WebhookConfig{URL: srv.URL + "/hook", Enabled: true, MinSeverity: "high"}); err != nil {
		t.Fatal(err)
	}
	if err := outbound.Save(ctx, store, &outbound.Settings{WebhookFormat: outbound.FormatTeams, UseAlertWebhook: true}, false, false); err != nil {
		t.Fatal(err)
	}
	res, err = s.Create(ctx, CreateRequest{HostID: host.ID, ServiceID: svc.ID, IssueKey: d.IssueKey}, "ana")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created || !res.Delivery.Delivered || res.Delivery.Channel != outbound.ChannelWebhook || res.Ticket.Status != StatusNotified {
		t.Fatalf("webhook delivery expected: %+v / %s", res.Delivery, res.Ticket.Status)
	}
	if len(h.bodies) != 1 || h.bodies[0]["@type"] != "MessageCard" || !strings.Contains(h.bodies[0]["title"].(string), "Telnet") {
		t.Fatalf("teams payload: %+v", h.bodies)
	}

	// Manual status: acknowledged.
	if _, err := s.UpdateStatus(ctx, res.Ticket.ID, StatusRequest{Status: StatusAcknowledged, Note: "owner replied"}, "ana"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateStatus(ctx, res.Ticket.ID, StatusRequest{Status: StatusOpen}, "ana"); err == nil {
		t.Fatal("acknowledged -> open must be refused")
	}

	// Scan still sees telnet: nothing changes.
	if out, _ := s.VerifyScan(ctx, "scan-a"); len(out) != 0 {
		t.Fatalf("no outcome expected: %+v", out)
	}
	// Owner turns telnet off; the next scan closes the port.
	svc.State = "closed"
	if _, err := store.UpsertObservedService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	out, err := s.VerifyScan(ctx, "scan-b")
	if err != nil || len(out) != 1 || out[0].Action != "verified_fixed" {
		t.Fatalf("verified fix expected: %+v %v", out, err)
	}
	got, _ := s.Repo.Get(ctx, res.Ticket.ID)
	if got.Status != StatusFixed || got.FixedScanID != "scan-b" || !got.Verified {
		t.Fatalf("ticket: %+v", got)
	}
	if len(fixed) != 1 || fixed[0] != got.ID+"@scan-b" {
		t.Fatalf("DefectDojo hook not called: %v", fixed)
	}
	want := []string{"remediation.create", "remediation.notify", "remediation.status", "remediation.verified_fixed"}
	if strings.Join(audits, ",") != strings.Join(want, ",") {
		t.Fatalf("audit: %v", audits)
	}
	st := ComputeStats([]Ticket{*got}, got.FixedAt.Add(time.Hour))
	if st.Fixed != 1 || st.FixedLast24h != 1 || st.Open != 0 {
		t.Fatalf("stats: %+v", st)
	}
}
