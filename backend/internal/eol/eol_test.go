package eol

import (
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

var asOf = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func TestEmbeddedTableLoads(t *testing.T) {
	d := Table()
	if d.AsOf == "" || d.DataVersion == "" {
		t.Fatal("data file must carry as_of and data_version")
	}
	for _, key := range []string{"nginx", "apache-httpd", "php", "tomcat", "iis", "wordpress", "drupal", "joomla", "jenkins", "grafana", "mysql", "mariadb", "postgresql", "redis", "openssl", "exim", "postfix", "openssh"} {
		p := d.byKey[key]
		if p == nil {
			t.Fatalf("product %s missing", key)
		}
		if !strings.HasPrefix(p.Source, "https://") {
			t.Fatalf("product %s must cite a source URL", key)
		}
	}
}

func TestMatchBranchDotBoundary(t *testing.T) {
	nginx := Table().LookupProduct("nginx")
	cases := map[string]string{
		"1.14.2":          "1.14",
		"1.18.0 (Ubuntu)": "1.18",
		"1.1.19":          "1.1",
		"1.10.3":          "1.10",
		"v1.24.0":         "1.24",
	}
	for v, want := range cases {
		b, ok := nginx.MatchBranch(v)
		if !ok || b.Cycle != want {
			t.Errorf("nginx %q -> %q (%v), want %q", v, b.Cycle, ok, want)
		}
	}
	if _, ok := nginx.MatchBranch("unknown"); ok {
		t.Error("non-numeric version must not match")
	}
	tomcat := Table().LookupProduct("Apache Tomcat")
	if b, _ := tomcat.MatchBranch("7.0.109"); b.Cycle != "7" {
		t.Errorf("tomcat 7.0.109 -> %q, want single-number cycle 7", b.Cycle)
	}
	jenkins := Table().LookupProduct("Jenkins")
	if b, _ := jenkins.MatchBranch("2.346.3"); b.Cycle != "2.346" || b.EOL == "" {
		t.Errorf("jenkins LTS 2.346.3 -> %+v, want LTS line 2.346 with EOL", b)
	}
	if b, _ := jenkins.MatchBranch("2.591"); b.Cycle != "2" || b.EOL != "" {
		t.Errorf("jenkins weekly 2.591 -> %+v, want supported weekly line", b)
	}
}

func TestAssessNginxFromServerHeader(t *testing.T) {
	svc := &domain.Service{Port: 80, ServiceName: "http", Product: "nginx", Version: "1.14.2",
		VersionSource: "http-server-header", HTTP: &domain.HTTPFingerprint{ServerHeader: "nginx/1.14.2"}}
	out, hints := Assess(svc, asOf)
	if len(out) != 1 || len(hints) != 0 {
		t.Fatalf("want one outdated component, got %+v %+v", out, hints)
	}
	o := out[0]
	if o.Branch != "1.14" || o.EOLDate != "2019-04-23" || o.Label != "nginx 1.14 – gałąź EOL od 2019-04" {
		t.Fatalf("unexpected component: %+v", o)
	}
	if o.DaysSinceEOL < 7*365 || o.DistroPackaged || o.Via != "http-server-header" {
		t.Fatalf("age/distro/via wrong: %+v", o)
	}
	for _, want := range []string{"2019-04-23", "7 lat", "endoflife.date/nginx", "dane z 2026-11-21", "Wspierana gałąź: 1.31"} {
		if !strings.Contains(o.Evidence, want) {
			t.Errorf("evidence %q lacks %q", o.Evidence, want)
		}
	}
}

func TestAssessDistroVersionStrings(t *testing.T) {
	// nginx 1.18.0 as packaged by Ubuntu 20.04: upstream branch EOL, distro build flagged.
	svc := &domain.Service{Product: "nginx", Version: "1.18.0",
		HTTP: &domain.HTTPFingerprint{ServerHeader: "nginx/1.18.0 (Ubuntu)"}}
	out, _ := Assess(svc, asOf)
	if len(out) != 1 || out[0].Branch != "1.18" || !out[0].DistroPackaged || !strings.Contains(out[0].Evidence, "backport") {
		t.Fatalf("nginx 1.18.0 (Ubuntu): %+v", out)
	}

	// OpenSSH has no EOL table but 8.9p1 is in the regreSSHion range; Ubuntu build -> caveat.
	ssh := &domain.Service{Port: 22, Product: "OpenSSH", Version: "8.9p1 Ubuntu-3ubuntu0.6",
		Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}
	out, hints := Assess(ssh, asOf)
	if len(out) != 0 {
		t.Fatalf("OpenSSH must never be EOL-flagged: %+v", out)
	}
	if len(hints) != 1 || hints[0].ID != "CVE-2024-6387" || !hints[0].DistroPackaged || !strings.Contains(hints[0].Evidence, "Pasywna") {
		t.Fatalf("regreSSHion hint: %+v", hints)
	}
	for _, v := range []string{"9.8p1", "9.9p1", "8.4p1", "7.4p1", "4.4p1"} {
		if _, h := Assess(&domain.Service{Product: "OpenSSH", Version: v}, asOf); len(h) != 0 {
			t.Errorf("OpenSSH %s must not get the regreSSHion hint: %+v", v, h)
		}
	}
	for _, v := range []string{"8.5p1", "9.7p1", "9.3", "4.3p2"} {
		if _, h := Assess(&domain.Service{Product: "OpenSSH", Version: v}, asOf); len(h) != 1 {
			t.Errorf("OpenSSH %s should get the regreSSHion hint", v)
		}
	}
}

func TestAssessServerHeaderModulesAndTech(t *testing.T) {
	svc := &domain.Service{Product: "Apache httpd", Version: "2.4.6",
		HTTP: &domain.HTTPFingerprint{
			ServerHeader: "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16",
			Headers:      map[string]string{"X-Powered-By": "PHP/5.4.16"},
		},
		Technologies: []domain.DetectedTechnology{{Name: "WordPress", Version: "4.5.3"}, {Name: "Apache HTTP Server", Version: "2.4.6"}},
	}
	out, _ := Assess(svc, asOf)
	got := map[string]string{}
	for _, o := range out {
		got[o.Product] = o.Branch
	}
	want := map[string]string{"OpenSSL": "1.0.2", "PHP": "5.4", "WordPress": "4.5"}
	for p, b := range want {
		if got[p] != b {
			t.Errorf("%s: got branch %q, want %q (all: %v)", p, got[p], b, got)
		}
	}
	if _, ok := got["Apache httpd"]; ok {
		t.Error("Apache 2.4 is supported and must not be flagged")
	}
	if len(out) != 3 || !out[0].DistroPackaged {
		t.Errorf("CentOS build should be marked distro-packaged: %+v", out)
	}
}

func TestAssessDatabasesAndIIS(t *testing.T) {
	cases := []struct {
		product, version, wantProduct, wantBranch string
	}{
		{"MySQL", "5.5.5-10.3.39-MariaDB-0+deb10u1", "MariaDB", "10.3"},
		{"MySQL", "5.7.33-0ubuntu0.18.04.1", "MySQL", "5.7"},
		{"PostgreSQL DB", "9.6.0 - 9.6.4", "PostgreSQL", "9.6"},
		{"Redis key-value store", "6.0.16", "Redis", "6.0"},
		{"Microsoft IIS httpd", "7.5", "Microsoft IIS", "7.5"},
		{"Exim smtpd", "4.92.3", "Exim", "4.92"},
	}
	for _, c := range cases {
		out, _ := Assess(&domain.Service{Product: c.product, Version: c.version}, asOf)
		if len(out) != 1 || out[0].Product != c.wantProduct || out[0].Branch != c.wantBranch {
			t.Errorf("%s %s -> %+v, want %s %s", c.product, c.version, out, c.wantProduct, c.wantBranch)
		}
	}
	for _, c := range [][2]string{{"Microsoft IIS httpd", "10.0"}, {"PostgreSQL DB", "16.4"}, {"Redis key-value store", "7.2.4"}, {"Apache httpd", "2.4.62"}} {
		if out, _ := Assess(&domain.Service{Product: c[0], Version: c[1]}, asOf); len(out) != 0 {
			t.Errorf("%s %s should be supported: %+v", c[0], c[1], out)
		}
	}
	// Coyote's connector version is not a Tomcat version.
	if out, _ := Assess(&domain.Service{Product: "Apache Tomcat/Coyote JSP engine", Version: "1.1"}, asOf); len(out) != 0 {
		t.Errorf("Coyote 1.1 must not be matched to Tomcat: %+v", out)
	}
}

func TestEOLBoundaryIsInclusive(t *testing.T) {
	svc := &domain.Service{Product: "PostgreSQL DB", Version: "14.20"} // branch 14 EOL 2026-11-12
	if out, _ := Assess(svc, time.Date(2026, 11, 11, 23, 0, 0, 0, time.UTC)); len(out) != 0 {
		t.Fatalf("day before EOL must not flag: %+v", out)
	}
	if out, _ := Assess(svc, time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)); len(out) != 1 {
		t.Fatal("EOL day itself must flag")
	}
}

func TestApplyScoreIdempotent(t *testing.T) {
	svc := &domain.Service{Product: "Apache httpd", Version: "2.4.49", Interestingness: 10,
		InterestingFactors: []domain.InterestingnessFactor{{Reason: "x", Points: 10}}}
	ApplyScore(svc, asOf)
	ApplyScore(svc, asOf)
	if len(svc.KnownVulns) != 2 { // CVE-2021-41773 + CVE-2021-42013
		t.Fatalf("hints: %+v", svc.KnownVulns)
	}
	if svc.Interestingness != 10+PointsKnownVuln || len(svc.InterestingFactors) != 2 {
		t.Fatalf("score not idempotent: %d %+v", svc.Interestingness, svc.InterestingFactors)
	}
	if !contains(svc.Tags, TagKnownVuln) || contains(svc.Tags, TagEOL) {
		t.Fatalf("tags: %v", svc.Tags)
	}
}

func TestCompareVersionsAndAge(t *testing.T) {
	if compareVersions("8.9p1", "9.8p1") >= 0 || compareVersions("8.5p1", "8.5p1") != 0 || compareVersions("8.5", "8.5p1") >= 0 {
		t.Fatal("openssh ordering")
	}
	if compareVersions("4.92", "4.92.0") != 0 || compareVersions("4.100", "4.99") <= 0 {
		t.Fatal("numeric ordering")
	}
	for days, want := range map[int]string{3000: "8 lat", 800: "2 lata", 400: "1 rok", 90: "3 mies.", 5: "5 dni", 22 * 365: "22 lata", 12 * 365: "12 lat"} {
		if got := Age(days); got != want {
			t.Errorf("Age(%d)=%q want %q", days, got, want)
		}
	}
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
