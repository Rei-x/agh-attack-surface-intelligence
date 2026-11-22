package defectdojo

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

// The payload tests of this package pin exact findings; the embedded NVD snapshot would add
// known-vulnerability findings that change with every data refresh, so the package runs on
// an empty snapshot and TestVulnAndVerifiedFields installs its own fixture.
func TestMain(m *testing.M) {
	empty, _ := vulndb.Parse([]byte(`{"schema":1,"products":{}}`))
	vulndb.SetCurrent(vulndb.New(empty, "test"))
	os.Exit(m.Run())
}

const ddVulnFixture = `{"schema":1,"generated_at":"2026-11-21T00:00:00Z",
 "cves":[
  {"id":"CVE-2016-10033","s":9.8,"sev":"CRITICAL","k":"2025-07-07","e":0.97,"ep":0.999,"d":"PHPMailer RCE"},
  {"id":"CVE-2017-0002","s":6.1,"sev":"MEDIUM","e":0.02,"ep":0.6}],
 "products":{"wordpress":[{"c":"CVE-2016-10033","r":[{"ei":"4.7"}]},{"c":"CVE-2017-0002","r":[{"ee":"4.7.19"}]}]}}`

func TestVulnAndVerifiedFields(t *testing.T) {
	snap, err := vulndb.Parse([]byte(ddVulnFixture))
	if err != nil {
		t.Fatal(err)
	}
	vulndb.SetCurrent(vulndb.New(snap, "test"))
	defer func() {
		empty, _ := vulndb.Parse([]byte(`{"schema":1,"products":{}}`))
		vulndb.SetCurrent(vulndb.New(empty, "test"))
	}()

	base := changesNow.Add(-10 * 24 * time.Hour)
	host := domain.Host{IP: "10.0.0.5", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow, Services: []domain.Service{{
		ID: "wp", Port: 8088, Protocol: "tcp", State: "open", ServiceName: "http", FirstSeen: base,
		Technologies: []domain.DetectedTechnology{{Name: "WordPress", Version: "4.7"}},
		Verified: []domain.VerifiedFinding{{CheckID: "wordpress-xmlrpc", Name: "WordPress XML-RPC enabled", Severity: "medium",
			Request: "POST http://10.0.0.5:8088/xmlrpc.php", Evidence: "HTTP/1.1 200 OK\n<methodResponse>pingback.ping", Remediation: "Block xmlrpc.php",
			CheckedAt: changesNow}},
	}}}
	findings := BuildChangeFindings([]domain.Host{host}, changesNow)
	var vuln, ver *ChangeFinding
	for i := range findings {
		switch findings[i].Kind {
		case KindKnownVuln:
			vuln = &findings[i]
		case KindVerified:
			ver = &findings[i]
		}
	}
	if vuln == nil || ver == nil {
		t.Fatalf("missing findings: %+v", findings)
	}
	if vuln.Severity != "Critical" || vuln.CVE != "CVE-2016-10033" || len(vuln.VulnerabilityIDs) != 1 || !vuln.KnownExploited || vuln.KEVDate != "2025-07-07" || vuln.EPSSScore != 0.97 || vuln.CVSSv3Score != 9.8 {
		t.Fatalf("vuln finding: %+v", vuln.genericFinding)
	}
	if !strings.HasPrefix(vuln.Title, "Known exploited vulnerability (CISA KEV): WordPress 4.7 on 10.0.0.5:8088/tcp") {
		t.Fatalf("title: %s", vuln.Title)
	}
	if !ver.Verified || ver.Severity != "Medium" || !strings.Contains(ver.StepsToReproduce, "pingback.ping") || strings.Contains(ver.Description, "pingback.ping") {
		t.Fatalf("verified finding: %+v", ver.genericFinding)
	}
	// The JSON carries only fields the Generic Findings parser allows.
	raw, _ := json.Marshal(vuln.genericFinding)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	allowed := map[string]bool{"title": true, "description": true, "severity": true, "date": true, "active": true, "verified": true, "unique_id_from_tool": true,
		"vuln_id_from_tool": true, "mitigation": true, "references": true, "component_name": true, "component_version": true, "tags": true, "endpoints": true,
		"cve": true, "vulnerability_ids": true, "cvssv3_score": true, "epss_score": true, "epss_percentile": true, "known_exploited": true, "kev_date": true,
		"ransomware_used": true, "severity_justification": true, "steps_to_reproduce": true, "impact": true, "service": true}
	for k := range m {
		if !allowed[k] {
			t.Errorf("field %q is not accepted by DefectDojo's generic parser", k)
		}
	}
	// Stable across runs: a later check time does not change title or description.
	host.Services[0].Verified[0].CheckedAt = changesNow.Add(time.Hour)
	host.Services[0].Verified[0].Evidence = "HTTP/1.1 200 OK\nDate: later"
	again := BuildChangeFindings([]domain.Host{host}, changesNow)
	for i := range again {
		if again[i].Kind == KindVerified && (again[i].Title != ver.Title || again[i].Description != ver.Description) {
			t.Fatal("verified finding hash inputs changed between runs")
		}
	}
}
