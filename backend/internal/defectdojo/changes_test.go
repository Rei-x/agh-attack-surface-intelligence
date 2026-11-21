package defectdojo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

var changesNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// fixtureHosts: baseline scan 10 days ago, one host with EOL nginx + RDP, one admin panel
// added yesterday, one host gone, one triaged as accepted risk.
func fixtureHosts() []domain.Host {
	base := changesNow.Add(-10 * 24 * time.Hour)
	yesterday := changesNow.Add(-24 * time.Hour)
	exp := changesNow.Add(30 * 24 * time.Hour)
	return []domain.Host{
		{
			IP: "10.66.0.12", Hostname: "www-old.wi", Owner: "admin@wi.agh.edu.pl", Tags: []string{"wydzial wi"},
			LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow,
			Services: []domain.Service{
				{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: "1.14.2",
					VersionSource: "http-server-header", FirstSeen: base, LastSeen: changesNow,
					HTTP: &domain.HTTPFingerprint{Scheme: "http", ServerHeader: "nginx/1.14.2"}},
				{Port: 3389, Protocol: "tcp", State: "open", ServiceName: "ms-wbt-server", FirstSeen: base, LastSeen: changesNow},
				{Port: 443, Protocol: "tcp", State: "closed", ServiceName: "https", Product: "nginx", Version: "1.10.3", FirstSeen: base},
				{Port: 8443, Protocol: "tcp", State: "open", ServiceName: "https", FirstSeen: base}, // baseline, boring
			},
		},
		{
			IP: "10.66.0.40", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow,
			Services: []domain.Service{
				{Port: 8080, Protocol: "tcp", State: "open", ServiceName: "http", Product: "Jetty", IsAdminPanel: true, FirstSeen: yesterday,
					Technologies: []domain.DetectedTechnology{{Name: "Jenkins", Category: "admin_panel"}}},
				{Port: 9000, Protocol: "tcp", State: "open", ServiceName: "http", FirstSeen: yesterday},
			},
		},
		{IP: "10.66.0.77", Owner: "lab@wi.agh.edu.pl", LifecycleState: domain.HostStateInactive, FirstSeen: base, LastSeen: changesNow.Add(-3 * 24 * time.Hour)},
		{IP: "10.66.0.78", LifecycleState: domain.HostStateInactive, FirstSeen: base, LastSeen: changesNow.Add(-90 * 24 * time.Hour)},
		{
			IP: "10.66.0.90", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow,
			Triage:   &domain.TriageInfo{Status: domain.TriageAcceptedRisk, Reason: "honeypot", ExpiresAt: &exp},
			Services: []domain.Service{{Port: 23, Protocol: "tcp", State: "open", ServiceName: "telnet", FirstSeen: base}},
		},
		{
			IP: "10.66.0.91", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow,
			Services: []domain.Service{{Port: 445, Protocol: "tcp", State: "open", ServiceName: "microsoft-ds", FirstSeen: base,
				Triage: &domain.TriageInfo{Status: domain.TriageFalsePositive, Reason: "sinkhole"}}},
		},
	}
}

func TestBuildChangeFindingsPayload(t *testing.T) {
	fs := BuildChangeFindings(fixtureHosts(), changesNow)
	byKind := map[string][]ChangeFinding{}
	for _, f := range fs {
		byKind[f.Kind] = append(byKind[f.Kind], f)
	}
	want := map[string]int{KindEOL: 1, KindExposure: 1, KindAdmin: 1, KindNew: 1, KindHostGone: 1}
	for k, n := range want {
		if len(byKind[k]) != n {
			t.Errorf("%s: got %d findings, want %d", k, len(byKind[k]), n)
		}
	}
	if len(fs) != 5 {
		for _, f := range fs {
			t.Logf("%s | %s", f.Kind, f.Title)
		}
		t.Fatalf("want 5 findings (suppressed, closed, baseline and long-gone items excluded), got %d", len(fs))
	}

	e := byKind[KindEOL][0]
	if e.Title != "nginx 1.14.2 – gałąź 1.14 EOL od 2019-04-23, na 10.66.0.12:80/tcp [właściciel: admin@wi.agh.edu.pl]" {
		t.Errorf("EOL title: %q", e.Title)
	}
	if e.Severity != "Medium" || e.ComponentName != "nginx" || e.ComponentVersion != "1.14.2" || e.Date != "2026-11-11" {
		t.Errorf("EOL fields: %+v", e.genericFinding)
	}
	for _, s := range []string{"**Właściciel (reguła CIDR):** admin@wi.agh.edu.pl", "**Pierwsze wykrycie:** 2026-11-11 12:00 UTC", "2019-04-23", "endoflife.date/nginx", "Wspierana gałąź: 1.31"} {
		if !strings.Contains(e.Description, s) {
			t.Errorf("EOL description lacks %q:\n%s", s, e.Description)
		}
	}
	if strings.Contains(e.Description, "temu") || strings.Contains(e.Description, "lat") {
		t.Errorf("description must not carry a time-relative age (breaks DefectDojo hash dedup):\n%s", e.Description)
	}
	if !reflect.DeepEqual(e.Tags, []string{"dzieciol", "aegis-asi", "eol", "owner:admin@wi.agh.edu.pl", "wydzial-wi"}) {
		t.Errorf("tags: %v", e.Tags)
	}
	if len(e.Endpoints) != 1 || e.Endpoints[0].Host != "10.66.0.12" || e.Endpoints[0].Port != 80 || e.Endpoints[0].Protocol != "http" {
		t.Errorf("endpoint: %+v", e.Endpoints)
	}

	if x := byKind[KindExposure][0]; !strings.HasPrefix(x.Title, "Ryzykowna usługa wystawiona: RDP (ms-wbt-server) na 10.66.0.12:3389/tcp") || x.Severity != "Medium" {
		t.Errorf("exposure: %q %s", x.Title, x.Severity)
	}
	if a := byKind[KindAdmin][0]; a.Title != "Panel administracyjny wystawiony: Jenkins na 10.66.0.40:8080/tcp" || !strings.Contains(a.Description, "brak — dodaj regułę CIDR") {
		t.Errorf("admin: %q\n%s", a.Title, a.Description)
	}
	if n := byKind[KindNew][0]; !strings.Contains(n.Title, "10.66.0.40:9000/tcp") || n.Severity != "Low" {
		t.Errorf("new service: %+v", n.genericFinding)
	}
	if g := byKind[KindHostGone][0]; g.Title != "Host zniknął z sieci: 10.66.0.77 (ostatnio widziany 2026-11-18) [właściciel: lab@wi.agh.edu.pl]" || g.Severity != "Info" {
		t.Errorf("host gone: %q %s", g.Title, g.Severity)
	}
	for _, f := range fs {
		if strings.Contains(f.Title, "10.66.0.90") || strings.Contains(f.Title, "10.66.0.91") {
			t.Errorf("suppressed item pushed: %s", f.Title)
		}
	}
}

// Dedup: the next run with the same state must produce byte-identical findings (DefectDojo
// then leaves them untouched), and unique ids must be distinct and stable.
func TestBuildChangeFindingsStableAcrossRuns(t *testing.T) {
	run1 := BuildChangeFindings(fixtureHosts(), changesNow)
	hosts := fixtureHosts()
	hosts[0].LastSeen = changesNow.Add(6 * time.Hour)
	hosts[0].Services[0].LastSeen = changesNow.Add(6 * time.Hour)
	hosts[0].Services[0].Interestingness = 42
	run2 := BuildChangeFindings(hosts, changesNow.Add(6*time.Hour))
	a, _ := json.Marshal(run1)
	b, _ := json.Marshal(run2)
	if string(a) != string(b) {
		t.Fatalf("payload changed between runs with the same state:\n%s\n%s", a, b)
	}
	seen := map[string]bool{}
	for _, f := range run1 {
		if !strings.HasPrefix(f.UniqueIDFromTool, "aegis-") || seen[f.UniqueIDFromTool] {
			t.Fatalf("unique_id_from_tool must be set and distinct: %+v", f.genericFinding)
		}
		seen[f.UniqueIDFromTool] = true
	}

	// Upgrade nginx to a supported branch: the EOL finding disappears (DefectDojo closes it).
	hosts[0].Services[0].Version = "1.30.1"
	hosts[0].Services[0].HTTP.ServerHeader = "nginx/1.30.1"
	for _, f := range BuildChangeFindings(hosts, changesNow) {
		if f.Kind == KindEOL {
			t.Fatalf("upgraded service still reported EOL: %s", f.Title)
		}
	}
}

func TestImportChangeFindingsRequest(t *testing.T) {
	var form map[string]string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/reimport-scan/" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseMultipartForm(1 << 20)
		form = map[string]string{}
		for k, v := range r.MultipartForm.Value {
			form[k] = v[0]
		}
		f, _, _ := r.FormFile("file")
		body, _ = io.ReadAll(f)
		_, _ = w.Write([]byte(`{"test":31,"engagement_id":1}`))
	}))
	defer srv.Close()
	cfg := &domain.DefectDojoConfig{URL: srv.URL, APIToken: "t"}
	fs := BuildChangeFindings(fixtureHosts(), changesNow)
	res, err := NewClient().ImportChangeFindings(context.Background(), cfg, 0, ChangesTestTitle("Kampus"), "run-9", fs)
	if err != nil || res.ExternalURL != srv.URL+"/test/31" {
		t.Fatalf("import: %+v %v", res, err)
	}
	if form["scan_type"] != "Generic Findings Import" || form["test_title"] != "Dzięcioł changes: Kampus" ||
		form["close_old_findings"] != "true" || form["auto_create_context"] != "true" || form["version"] != "run-9" {
		t.Fatalf("form: %+v", form)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Findings) != len(fs) {
		t.Fatalf("payload: %v %s", err, body)
	}
	if _, leaked := doc.Findings[0]["Kind"]; leaked {
		t.Fatal("internal fields must not be serialised")
	}

	// No findings left: still reimport (empty list) so DefectDojo closes the old ones.
	if _, err := NewClient().ImportChangeFindings(context.Background(), cfg, 0, "t", "", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"findings":[]`) {
		t.Fatalf("empty import must send an empty list: %s", body)
	}
}

// TestRealDefectDojoChangeFindings checks dedup and closing against a live instance:
//
//	AEGIS_DD_URL=http://localhost:8081 AEGIS_DD_TOKEN=... go test ./internal/defectdojo -run RealDefectDojoChange -v
func TestRealDefectDojoChangeFindings(t *testing.T) {
	url, token := os.Getenv("AEGIS_DD_URL"), os.Getenv("AEGIS_DD_TOKEN")
	if url == "" || token == "" {
		t.Skip("AEGIS_DD_URL/AEGIS_DD_TOKEN not set")
	}
	cfg := &domain.DefectDojoConfig{URL: url, APIToken: token}
	c := NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	title := ChangesTestTitle("integration-" + time.Now().UTC().Format("20060102-150405"))
	count := func(testID int, extra string) int {
		var page struct {
			Count int `json:"count"`
		}
		if err := c.getJSON(ctx, cfg, "/api/v2/findings/?test="+itoa(testID)+extra, &page); err != nil {
			t.Fatal(err)
		}
		return page.Count
	}

	fs := BuildChangeFindings(fixtureHosts(), changesNow)
	r1, err := c.ImportChangeFindings(ctx, cfg, 0, title, "run-1", fs)
	if err != nil || r1.TestID == 0 {
		t.Fatalf("import 1: %+v %v", r1, err)
	}
	// Same state again (later run): nothing new, nothing duplicated.
	r2, err := c.ImportChangeFindings(ctx, cfg, 0, title, "run-2", BuildChangeFindings(fixtureHosts(), changesNow.Add(time.Hour)))
	if err != nil || r2.TestID != r1.TestID {
		t.Fatalf("import 2 must hit the same test: %+v %v", r2, err)
	}
	if total, active := count(r1.TestID, ""), count(r1.TestID, "&active=true"); total != len(fs) || active != len(fs) {
		t.Fatalf("after identical reimport want %d findings, got total=%d active=%d", len(fs), total, active)
	}
	// nginx upgraded: its EOL finding is closed (mitigated), the rest stays.
	hosts := fixtureHosts()
	hosts[0].Services[0].Version, hosts[0].Services[0].HTTP.ServerHeader = "1.30.1", "nginx/1.30.1"
	if _, err := c.ImportChangeFindings(ctx, cfg, 0, title, "run-3", BuildChangeFindings(hosts, changesNow)); err != nil {
		t.Fatal(err)
	}
	if active, mitigated := count(r1.TestID, "&active=true"), count(r1.TestID, "&is_mitigated=true"); active != len(fs)-1 || mitigated != 1 {
		t.Fatalf("after upgrade want %d active / 1 mitigated, got %d / %d", len(fs)-1, active, mitigated)
	}
	t.Logf("change test %s: %d findings, dedup + close verified", r1.ExternalURL, len(fs))
}
