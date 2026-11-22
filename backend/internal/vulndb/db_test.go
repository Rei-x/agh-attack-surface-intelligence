package vulndb

import (
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func testSnapshot() *Snapshot {
	s := &Snapshot{
		Schema:      SchemaVersion,
		GeneratedAt: "2026-11-21T12:00:00Z",
		CVEs: []CVE{
			{ID: "CVE-2021-41773", CVSS: 7.5, Severity: "HIGH", Summary: "Path traversal in Apache 2.4.49"},
			{ID: "CVE-2021-42013", CVSS: 9.8, Severity: "CRITICAL", Summary: "Path traversal and RCE in Apache 2.4.49 and 2.4.50"},
			{ID: "CVE-2024-6387", CVSS: 8.1, Severity: "HIGH", Summary: "regreSSHion"},
			{ID: "CVE-2017-0001", CVSS: 4.3, Severity: "MEDIUM"},
			{ID: "CVE-2017-0002", CVSS: 6.1, Severity: "MEDIUM"},
		},
		Products: map[string][]Affected{
			"apache-httpd": {
				{CVE: "CVE-2021-41773", Ranges: []Range{{Exact: "2.4.49"}}},
				{CVE: "CVE-2021-42013", Ranges: []Range{{Exact: "2.4.49"}, {Exact: "2.4.50"}}},
			},
			"openssh": {{CVE: "CVE-2024-6387", Ranges: []Range{{SI: "8.5p1", EE: "9.8p1"}}}},
			"wordpress": {
				{CVE: "CVE-2017-0001", Ranges: []Range{{SI: "4.7", EE: "4.7.2"}}},
				{CVE: "CVE-2017-0002", Ranges: []Range{{EE: "4.7.19"}}},
			},
		},
	}
	s.index()
	return s
}

func TestKEVAndEPSSJoin(t *testing.T) {
	s := testSnapshot()
	ApplyKEV(s, "2026.11.20", "test", func(yield func(id, added string, ransomware bool)) {
		yield("CVE-2021-41773", "2021-11-03", false)
		yield("CVE-2021-42013", "2021-11-03", true)
		yield("CVE-1999-9999", "2021-11-03", false) // not in the snapshot: ignored
	})
	csv := "#model_version:v2026.06.15,score_date:2026-11-21T12:00:24Z\ncve,epss,percentile\nCVE-2021-41773,0.94400,0.99950\nCVE-2021-42013,0.94000,0.99900\nCVE-2024-6387,0.40000,0.97000\nCVE-2000-0001,0.1,0.5\n"
	n, err := ApplyEPSS(s, strings.NewReader(csv), "test")
	if err != nil || n != 3 {
		t.Fatalf("ApplyEPSS = %d, %v", n, err)
	}
	if s.Sources.EPSSModel != "v2026.06.15" || s.Sources.EPSSDate != "2026-11-21" {
		t.Fatalf("epss metadata: %+v", s.Sources)
	}
	c := s.byID["CVE-2021-42013"]
	if c.KEVAdded != "2021-11-03" || !c.Ransomware || c.EPSS != 0.94 || c.EPSSPct != 0.999 {
		t.Fatalf("joined record: %+v", c)
	}
	if s.byID["CVE-2017-0001"].KEVAdded != "" {
		t.Fatal("unlisted CVE marked as KEV")
	}
	// A re-join resets marks of CVEs that left the catalog.
	ApplyKEV(s, "2026.11.21", "test", func(yield func(id, added string, ransomware bool)) {})
	if s.byID["CVE-2021-41773"].KEVAdded != "" {
		t.Fatal("KEV mark not reset")
	}

	// Round trip through the compressed encoding.
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil || len(back.CVEs) != len(s.CVEs) || back.byID["CVE-2024-6387"].EPSS != 0.4 {
		t.Fatalf("round trip: %v", err)
	}
}

func joined() *DB {
	s := testSnapshot()
	ApplyKEV(s, "v", "t", func(yield func(id, added string, ransomware bool)) {
		yield("CVE-2021-41773", "2021-11-03", false)
		yield("CVE-2021-42013", "2021-11-03", false)
	})
	_, _ = ApplyEPSS(s, strings.NewReader("cve,epss,percentile\nCVE-2021-41773,0.944,0.9995\nCVE-2021-42013,0.94,0.999\nCVE-2024-6387,0.4,0.97\n"), "t")
	return New(s, "test")
}

func TestAssessApacheKEV(t *testing.T) {
	d := joined()
	svc := &domain.Service{Port: 80, ServiceName: "http", Product: "Apache httpd", Version: "2.4.49", VersionSource: "nmap"}
	vs := d.Assess(svc)
	if len(vs) != 1 {
		t.Fatalf("got %d summaries", len(vs))
	}
	v := vs[0]
	if v.Total != 2 || v.KEV != 2 || v.Critical != 1 || v.High != 1 || v.MaxCVSS != 9.8 || v.Confidence != "high" {
		t.Fatalf("summary: %+v", v)
	}
	if v.Top[0].ID != "CVE-2021-41773" || !v.Top[0].KEV || v.Top[0].URL != "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" {
		t.Fatalf("top ordering (KEV, then EPSS): %+v", v.Top)
	}
	// Both high-EPSS CVEs are the KEV ones: their EPSS is the same evidence and adds no
	// separate factor.
	f := Factors(vs)
	if len(f) != 2 || f[0].Points != PointsKEV || f[1].Points != PointsCVSSCritical {
		t.Fatalf("factors: %+v", f)
	}
	// 2.4.51 is fixed.
	if got := d.Assess(&domain.Service{Product: "Apache httpd", Version: "2.4.51"}); got != nil {
		t.Fatalf("2.4.51 matched: %+v", got)
	}
}

func TestAssessDistroBackport(t *testing.T) {
	d := joined()
	// Ubuntu 22.04 at 3ubuntu0.10 carries the regreSSHion fix (USN-6859-1).
	svc := &domain.Service{Port: 22, ServiceName: "ssh", Product: "OpenSSH", Version: "8.9p1 Ubuntu 3ubuntu0.10", Banner: "Ubuntu Linux; protocol 2.0"}
	vs := d.Assess(svc)
	if len(vs) != 1 || vs[0].Confidence != "low" || !vs[0].DistroBackport || vs[0].Total != 0 || vs[0].BackportedCount != 1 ||
		vs[0].Backported[0].Applicability != domain.ApplicabilityFixedByDistro || !strings.Contains(vs[0].ConfidenceNote, "Ubuntu 22.04") {
		t.Fatalf("distro: %+v", vs)
	}
	// Backported matches add no points at all.
	if f := Factors(vs); len(f) != 0 {
		t.Fatalf("distro build scored: %+v", f)
	}
	// 3ubuntu0.6 predates the fix: the match is confirmed and counted.
	svc.Version = "8.9p1 Ubuntu 3ubuntu0.6"
	vs = d.Assess(svc)
	if len(vs) != 1 || vs[0].Total != 1 || vs[0].DistroBackport || vs[0].Confidence != "high" || vs[0].Top[0].Applicability != domain.ApplicabilityDistroUnfixed {
		t.Fatalf("unfixed distro: %+v", vs)
	}
}

func TestAssessTechnologyAndHeaders(t *testing.T) {
	d := joined()
	svc := &domain.Service{
		Port: 8088, ServiceName: "http", Product: "Apache httpd", Version: "2.4.10",
		HTTP:         &domain.HTTPFingerprint{ServerHeader: "Apache/2.4.10 (Debian)"},
		Technologies: []domain.DetectedTechnology{{Name: "WordPress", Version: "4.7"}},
	}
	vs := d.Assess(svc)
	var wp *domain.VulnSummary
	for i := range vs {
		if vs[i].Product == "WordPress" {
			wp = &vs[i]
		}
	}
	if wp == nil || wp.Total != 2 || wp.Possible != 0 || wp.Confidence != "medium" || wp.Via != "technology" {
		t.Fatalf("wordpress: %+v", vs)
	}
	// Fresh WordPress install page: no generator, version from the core asset URLs only.
	install := &domain.Service{
		Port: 8088, ServiceName: "http",
		HTTP: &domain.HTTPFingerprint{BodySnippet: `<script src='http://x/wp-includes/js/jquery/jquery.js?ver=1.12.4'></script>` +
			`<link rel='stylesheet' href='http://x/wp-admin/load-styles.php?c=0&amp;dir=ltr&amp;load%5B%5D=dashicons,buttons&amp;ver=4.7.5' />`},
		Technologies: []domain.DetectedTechnology{{Name: "WordPress"}},
	}
	got := d.Assess(install)
	if len(got) != 1 || got[0].Version != "4.7.5" || got[0].Via != "http-page" || got[0].Confidence != "medium" {
		t.Fatalf("install page: %+v", got)
	}
	// An incomplete nginx-style version is "possible".
	hits := d.Lookup("wordpress", "4")
	if len(hits) == 0 || !hits[0].Possible {
		t.Fatalf("partial wordpress 4: %+v", hits)
	}
}

func TestAnnotateDropsCoveredHints(t *testing.T) {
	SetCurrent(joined())
	defer SetCurrent(nil)
	svc := &domain.Service{Product: "Apache httpd", Version: "2.4.49", KnownVulns: []domain.VulnHint{{ID: "CVE-2021-41773"}, {ID: "CVE-2019-10149"}}}
	f := Annotate(svc, testNow)
	if len(svc.Vulns) != 1 || len(f) == 0 {
		t.Fatalf("annotate: %+v %+v", svc.Vulns, f)
	}
	if len(svc.KnownVulns) != 1 || svc.KnownVulns[0].ID != "CVE-2019-10149" {
		t.Fatalf("covered hint kept: %+v", svc.KnownVulns)
	}
}

// TestEmbeddedSnapshot checks the committed data on the jury-lab products.
func TestEmbeddedSnapshot(t *testing.T) {
	s, err := Parse(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.CVEs) < 1000 || s.Sources.KEVVersion == "" || s.Sources.EPSSDate == "" {
		t.Skipf("embedded snapshot is a placeholder (%d CVEs)", len(s.CVEs))
	}
	d := New(s, "embedded")
	wp := d.Lookup("wordpress", "4.7")
	if len(wp) < 20 {
		t.Fatalf("WordPress 4.7: only %d CVEs", len(wp))
	}
	apache := d.Lookup("apache-httpd", "2.4.49")
	found := false
	for _, h := range apache {
		if h.CVE.ID == "CVE-2021-41773" {
			found = h.CVE.KEVAdded != "" && !h.Possible
		}
	}
	if !found {
		t.Fatal("Apache 2.4.49: CVE-2021-41773 missing or not KEV")
	}
	ssh := d.Lookup("openssh", "8.9p1")
	found = false
	for _, h := range ssh {
		found = found || h.CVE.ID == "CVE-2024-6387"
	}
	if !found {
		t.Fatal("OpenSSH 8.9p1: CVE-2024-6387 missing")
	}
	if got := d.Lookup("openssh", "9.9p2"); len(got) > 5 {
		t.Logf("OpenSSH 9.9p2: %d CVEs", len(got))
	}
}
