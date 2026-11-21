package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

func zoneFromPreset(t *testing.T, id, name string, cidrs ...string) domain.PolicyZone {
	t.Helper()
	p, ok := PresetByID(id)
	if !ok {
		t.Fatalf("preset %s missing", id)
	}
	z := domain.PolicyZone{ID: "z-" + id, Name: name, CIDRs: cidrs, Enabled: true, Preset: id, Rules: p.Rules}
	if err := NormalizeZone(&z); err != nil {
		t.Fatal(err)
	}
	return z
}

func host(id, ip string, svcs ...domain.Service) domain.Host {
	for i := range svcs {
		svcs[i].HostID = id
		svcs[i].HostIP = ip
		if svcs[i].ID == "" {
			svcs[i].ID = id + "-" + svcs[i].ServiceName
		}
		if svcs[i].State == "" {
			svcs[i].State = "open"
		}
		if svcs[i].Protocol == "" {
			svcs[i].Protocol = "tcp"
		}
	}
	return domain.Host{ID: id, IP: ip, LifecycleState: domain.HostStateActive, Services: svcs}
}

func byHost(vs []domain.PolicyViolation) map[string][]domain.PolicyViolation {
	m := map[string][]domain.PolicyViolation{}
	for _, v := range vs {
		m[v.HostIP] = append(m[v.HostIP], v)
	}
	return m
}

func hasRule(v domain.PolicyViolation, rule string) bool {
	for _, r := range v.Rules {
		if r == rule {
			return true
		}
	}
	return false
}

func TestPresetsAreValid(t *testing.T) {
	for _, p := range Presets {
		z := domain.PolicyZone{Name: p.Name, CIDRs: []string{"10.0.0.0/8"}, Rules: p.Rules}
		if err := NormalizeZone(&z); err != nil {
			t.Fatalf("preset %s does not validate: %v", p.ID, err)
		}
	}
	// PresetByID returns a copy: editing it must not change the built-in preset.
	p, _ := PresetByID(PresetServerWeb)
	p.Rules.AllowedPorts[0] = 9999
	again, _ := PresetByID(PresetServerWeb)
	if again.Rules.AllowedPorts[0] == 9999 {
		t.Fatal("PresetByID must not alias the built-in slices")
	}
}

func TestNormalizeZoneRejectsBadInput(t *testing.T) {
	cases := []domain.PolicyZone{
		{Name: "", CIDRs: []string{"10.0.0.0/8"}},
		{Name: "x", CIDRs: nil},
		{Name: "x", CIDRs: []string{"10.0.0.0/33"}},
		{Name: "x", CIDRs: []string{"10.0.0.0/8"}, Rules: domain.PolicyRules{AllowedPorts: []int{70000}}},
		{Name: "x", CIDRs: []string{"10.0.0.0/8"}, Rules: domain.PolicyRules{Forbidden: []string{"nope"}}},
		{Name: "x", CIDRs: []string{"10.0.0.0/8"}, Rules: domain.PolicyRules{MaxRisk: 101}},
	}
	for i, z := range cases {
		if err := NormalizeZone(&z); err == nil {
			t.Fatalf("case %d must fail: %+v", i, z)
		}
	}
	z := domain.PolicyZone{Name: " Lab ", CIDRs: []string{"10.66.0.7/24", "10.66.0.1", "10.66.0.0/24"}, Rules: domain.PolicyRules{
		AllowedPorts: []int{443, 22, 443}, Forbidden: []string{" Database ", "database"},
	}}
	if err := NormalizeZone(&z); err != nil {
		t.Fatal(err)
	}
	if z.Name != "Lab" || strings.Join(z.CIDRs, ",") != "10.66.0.0/24,10.66.0.1/32" ||
		len(z.Rules.AllowedPorts) != 2 || z.Rules.AllowedPorts[0] != 22 || len(z.Rules.Forbidden) != 1 {
		t.Fatalf("normalised zone: %+v", z)
	}
}

func TestEvaluatePresetsPortsAndCategories(t *testing.T) {
	now := time.Now().UTC()
	zones := []domain.PolicyZone{
		zoneFromPreset(t, PresetDefault, "Baseline", "10.66.0.0/18"),
		zoneFromPreset(t, PresetServerWeb, "Servers", "10.66.0.0/24"),
		zoneFromPreset(t, PresetManagement, "Mgmt", "10.66.4.0/24"),
		zoneFromPreset(t, PresetUserNetwork, "Students", "10.66.16.0/20"),
	}
	idrac := domain.Service{Port: 443, ServiceName: "https", IsAdminPanel: true,
		Technologies: []domain.DetectedTechnology{{Name: "Server BMC (Dell iDRAC / HPE iLO)"}}}
	hosts := []domain.Host{
		// Server zone: web is fine, RDP is not on the allowed list, postgres is forbidden.
		host("h1", "10.66.0.10",
			domain.Service{Port: 443, ServiceName: "https"},
			domain.Service{Port: 22, ServiceName: "ssh"},
			domain.Service{Port: 3389, ServiceName: "ms-wbt-server"},
			domain.Service{Port: 5432, ServiceName: "postgresql"},
		),
		// BMC in the server zone breaks it; the same BMC in the management VLAN is fine.
		host("h2", "10.66.0.246", idrac),
		host("h3", "10.66.4.5", idrac),
		// User network: any service, plus telnet is also cleartext.
		host("h4", "10.66.17.3", domain.Service{Port: 23, ServiceName: "telnet"}),
		// Baseline zone (no specific zone): web is fine, ftp is cleartext, mysql exposed.
		host("h5", "10.66.2.7",
			domain.Service{Port: 80, ServiceName: "http"},
			domain.Service{Port: 21, ServiceName: "ftp"},
			domain.Service{Port: 3306, ServiceName: "mysql"},
		),
		// Outside every zone: nothing to check.
		host("h6", "192.168.1.1", domain.Service{Port: 23, ServiceName: "telnet"}),
	}
	got := byHost(Evaluate(zones, hosts, now))

	h1 := got["10.66.0.10"]
	if len(h1) != 2 {
		t.Fatalf("server zone host: want RDP + postgres, got %+v", h1)
	}
	for _, v := range h1 {
		if v.ZoneName != "Servers" {
			t.Fatalf("most specific zone must win, got %s", v.ZoneName)
		}
		switch v.Port {
		case 3389:
			if v.Rule != domain.PolicyRulePort || v.Severity != "medium" {
				t.Fatalf("RDP: %+v", v)
			}
		case 5432:
			if v.Rule != "forbidden:database" || !hasRule(v, domain.PolicyRulePort) || v.Severity != "high" {
				t.Fatalf("postgres must be forbidden:database first, then port: %+v", v)
			}
		default:
			t.Fatalf("unexpected violation %+v", v)
		}
	}
	if v := got["10.66.0.246"]; len(v) != 1 || !hasRule(v[0], "forbidden:iot_bmc") || !strings.Contains(strings.Join(v[0].Evidence, " "), "management VLAN") {
		t.Fatalf("BMC outside management VLAN: %+v", v)
	}
	if v := got["10.66.4.5"]; len(v) != 0 {
		t.Fatalf("BMC inside management VLAN must be allowed: %+v", v)
	}
	if v := got["10.66.17.3"]; len(v) != 1 || v[0].Rule != "forbidden:cleartext_admin" || !hasRule(v[0], domain.PolicyRuleNoServices) {
		t.Fatalf("telnet in user network: %+v", v)
	}
	if v := got["10.66.2.7"]; len(v) != 2 {
		t.Fatalf("baseline: ftp + mysql, got %+v", v)
	}
	if v := got["192.168.1.1"]; len(v) != 0 {
		t.Fatalf("host outside zones must not be checked: %+v", v)
	}
}

func TestEvaluateTLSRiskAndExclusions(t *testing.T) {
	now := time.Now().UTC()
	z := domain.PolicyZone{ID: "z", Name: "Web", CIDRs: []string{"10.0.0.0/24"}, Enabled: true,
		Rules: domain.PolicyRules{RequireTLS: true, MaxRisk: 60}}
	accepted := domain.Service{Port: 8080, ServiceName: "http", Triage: &domain.TriageInfo{Status: domain.TriageAcceptedRisk}}
	hosts := []domain.Host{
		host("a", "10.0.0.1",
			domain.Service{Port: 80, ServiceName: "http", HTTP: &domain.HTTPFingerprint{URL: "http://10.0.0.1/"}},
			domain.Service{Port: 81, ServiceName: "http", HTTP: &domain.HTTPFingerprint{URL: "http://10.0.0.1:81/",
				RedirectChain: []domain.RedirectHop{{URL: "https://10.0.0.1/", StatusCode: 301}}}},
			domain.Service{Port: 443, ServiceName: "https", Interestingness: 75},
			domain.Service{Port: 8000, ServiceName: "http", State: "closed"},
			accepted,
		),
	}
	missing := host("b", "10.0.0.2", domain.Service{Port: 80, ServiceName: "http"})
	missing.LifecycleState = domain.HostStateMissing
	hosts = append(hosts, missing)

	got := Evaluate([]domain.PolicyZone{z}, hosts, now)
	if len(got) != 2 {
		t.Fatalf("want plain HTTP on 80 and risk on 443, got %+v", got)
	}
	for _, v := range got {
		switch v.Port {
		case 80:
			if v.Rule != domain.PolicyRuleTLS || v.Severity != "low" {
				t.Fatalf("TLS: %+v", v)
			}
		case 443:
			if v.Rule != domain.PolicyRuleMaxRisk {
				t.Fatalf("risk: %+v", v)
			}
		default:
			t.Fatalf("unexpected (closed, redirected, accepted risk or missing host): %+v", v)
		}
	}
	// A disabled zone checks nothing.
	z.Enabled = false
	if got := Evaluate([]domain.PolicyZone{z}, hosts, now); len(got) != 0 {
		t.Fatalf("disabled zone: %+v", got)
	}
}

func TestMergeOpensResolvesAndReopens(t *testing.T) {
	t0 := time.Now().UTC().Add(-2 * time.Hour)
	v := domain.PolicyViolation{ID: "pv-1", ZoneName: "Z", Rule: domain.PolicyRuleNoServices, Rules: []string{domain.PolicyRuleNoServices},
		Severity: "medium", HostID: "h", HostIP: "10.0.0.1", Port: 22, Owner: "it@agh"}

	led, ev := Merge(nil, []domain.PolicyViolation{v}, t0)
	if len(led) != 1 || len(ev) != 1 || ev[0].EventType != domain.EventPolicyViolation || ev[0].After["owner"] != "it@agh" {
		t.Fatalf("new violation: %+v %+v", led, ev)
	}
	t1 := t0.Add(time.Hour)
	led, ev = Merge(led, []domain.PolicyViolation{v}, t1)
	if len(ev) != 0 || !led[0].FirstSeen.Equal(t0) || !led[0].LastSeen.Equal(t1) {
		t.Fatalf("still present: no event, first seen kept: %+v %+v", led, ev)
	}
	t2 := t1.Add(time.Hour)
	led, ev = Merge(led, nil, t2)
	if len(ev) != 1 || ev[0].EventType != domain.EventPolicyResolved || led[0].Status != domain.PolicyStatusResolved || led[0].ResolvedAt == nil {
		t.Fatalf("gone: resolved: %+v %+v", led, ev)
	}
	led, ev = Merge(led, nil, t2.Add(time.Minute))
	if len(ev) != 0 || len(led) != 1 {
		t.Fatalf("resolved stays in history without new events: %+v %+v", led, ev)
	}
	led, ev = Merge(led, []domain.PolicyViolation{v}, t2.Add(2*time.Minute))
	if len(ev) != 1 || ev[0].EventType != domain.EventPolicyViolation || !strings.Contains(ev[0].Summary, "again") ||
		led[0].Status != domain.PolicyStatusOpen || led[0].ResolvedAt != nil || !led[0].FirstSeen.Equal(t0) {
		t.Fatalf("reappeared: reopened: %+v %+v", led, ev)
	}
	// Old resolved entries age out.
	led, _ = Merge(led, nil, t2)
	led, _ = Merge(led, nil, t2.Add(resolvedKeep+time.Hour))
	if len(led) != 0 {
		t.Fatalf("resolved history must expire: %+v", led)
	}
}

// End to end: ingest through the pipeline with the engine hook, violation appears with an
// event and owner, is queryable, and resolves when the port closes on the next scan.
func TestEngineThroughPipelineResolvesOnDisappear(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	rules := []domain.TagRule{{CIDR: "10.66.16.0/20", Owner: "lab-admin@agh.edu.pl", Enabled: true}}
	_ = ingest.NormalizeTagRule(&rules[0])
	_ = store.SaveSetting(ctx, db.SettingTagRules, rules)
	if _, err := SaveZones(ctx, store, []domain.PolicyZone{zoneFromPreset(t, PresetUserNetwork, "Students", "10.66.16.0/20")}, "test"); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(store)
	db.SetPolicyMatcher(eng)
	defer db.SetPolicyMatcher(nil)
	p := ingest.NewPipeline(store, ingest.NewDefaultAnalyzer(), nil)
	p.SetPostIngestHook(func(ctx context.Context, _ *domain.ScanRun) []domain.ChangeEvent {
		ev, err := eng.Evaluate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	})
	scan := func(ports ...int) *ingest.IngestResult {
		var svcs []domain.ObservedService
		for _, port := range ports {
			svcs = append(svcs, domain.ObservedService{Port: port, Protocol: "tcp", State: "open", ServiceName: map[int]string{22: "ssh", 3306: "mysql"}[port]})
		}
		res, err := p.ProcessObservations(ctx, ingest.IngestRequest{RunType: domain.ScanTypeManual,
			Observations: []domain.ObservedHost{{IP: "10.66.17.9", IsAlive: true, ObservedAt: time.Now(), Services: svcs}}})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	count := func(res *ingest.IngestResult, typ string) (n int, last domain.ChangeEvent) {
		for _, ev := range res.Changes {
			if ev.EventType == typ {
				n++
				last = ev
			}
		}
		return n, last
	}

	res := scan(22, 3306)
	n, ev := count(res, domain.EventPolicyViolation)
	if n != 2 || ev.ScanRunID != res.ScanRun.ID || ev.After["owner"] != "lab-admin@agh.edu.pl" {
		t.Fatalf("two violations with scan id and owner expected: %d %+v", n, ev)
	}
	st := eng.State(ctx)
	if len(st.Violations) != 2 || st.Violations[0].Owner != "lab-admin@agh.edu.pl" {
		t.Fatalf("ledger: %+v", st.Violations)
	}
	// Query language: violation:true / policy:<zone> / policy:<category>.
	for q, want := range map[string]int{"violation:true": 1, "policy:students": 1, "policy:database": 1, "policy:nosuch": 0, "-violation:true": 0} {
		hosts, _, err := store.ListHosts(ctx, db.HostFilter{Query: q})
		if err != nil || len(hosts) != want {
			t.Fatalf("query %q: want %d hosts, got %d (%v)", q, want, len(hosts), err)
		}
	}
	svcs, _ := store.ListServices(ctx, db.ServiceFilter{Query: "policy:database"})
	if len(svcs) != 1 || svcs[0].Port != 3306 {
		t.Fatalf("service query policy:database: %+v", svcs)
	}
	eng.AnnotateServices(svcs)
	if len(svcs[0].PolicyViolations) != 1 || svcs[0].PolicyViolations[0].ZoneName != "Students" {
		t.Fatalf("annotation: %+v", svcs[0].PolicyViolations)
	}

	// Same scan again: no new events.
	if n, _ := count(scan(22, 3306), domain.EventPolicyViolation); n != 0 {
		t.Fatalf("repeat scan must stay quiet, got %d", n)
	}
	// MySQL gone: its violation resolves, SSH stays open.
	res = scan(22)
	if n, ev := count(res, domain.EventPolicyResolved); n != 1 || ev.Port != 3306 {
		t.Fatalf("mysql violation must resolve: %d %+v", n, ev)
	}
	open := 0
	for _, v := range eng.State(ctx).Violations {
		if v.Status == domain.PolicyStatusOpen {
			open++
		}
	}
	if open != 1 || eng.OpenCount() != 1 {
		t.Fatalf("one open violation left, got %d", open)
	}

	// Policy change: removing the zone resolves the rest.
	if _, err := SaveZones(ctx, store, nil, "test"); err != nil {
		t.Fatal(err)
	}
	events, err := eng.Evaluate(ctx)
	if err != nil || len(events) != 1 || events[0].EventType != domain.EventPolicyResolved {
		t.Fatalf("zone removal must resolve: %+v %v", events, err)
	}
	recorded := eng.RecordEvents(ctx, events, nil)
	stored, _ := store.ListChangeEvents(ctx, db.ChangeFilter{EventType: domain.EventPolicyResolved})
	if len(recorded) != 1 || recorded[0].ID == "" || len(stored) < 2 {
		t.Fatalf("recorded events: %+v stored %d", recorded, len(stored))
	}
}

func TestDemoZonesSeedOnce(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	if ok, err := SeedDemo(ctx, store); !ok || err != nil {
		t.Fatalf("first seed: %v %v", ok, err)
	}
	zones, _ := LoadZones(ctx, store)
	if len(zones) != len(DemoZones()) {
		t.Fatalf("seeded %d zones", len(zones))
	}
	// Operator empties the list: never re-seeded.
	_, _ = SaveZones(ctx, store, nil, "admin")
	if ok, _ := SeedDemo(ctx, store); ok {
		t.Fatal("must not re-seed after zones were saved")
	}
}
