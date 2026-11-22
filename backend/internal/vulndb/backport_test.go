package vulndb

import (
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// The table rows must be well formed and cite the CVE they are about.
func TestDistroFixTable(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range distroFixes {
		key := f.CVE + "/" + f.Distro + "/" + f.Release
		if seen[key] {
			t.Errorf("duplicate row %s", key)
		}
		seen[key] = true
		up, rev := splitDebianVersion(f.Fixed)
		if up == "" || rev == "" || !strings.HasPrefix(f.Fixed, "1:") {
			t.Errorf("%s: fixed version %q is not epoch:upstream-revision", key, f.Fixed)
		}
		if defByKey(f.Product) == nil || !strings.HasSuffix(f.Source, f.CVE) {
			t.Errorf("%s: product %q / source %q", key, f.Product, f.Source)
		}
		if f.Distro == "Debian" && debianCodenames[f.Release] == "" || f.Distro == "Ubuntu" && ubuntuCodenames[f.Release] == "" {
			t.Errorf("%s: unknown release", key)
		}
	}
}

func TestDistroApplicability(t *testing.T) {
	deb := func(rev string) *domain.DistroPackage {
		return ParseDistroPackage("openssh", "9.2p1 Debian "+rev, "protocol 2.0")
	}
	ubu := func(up, rev string) *domain.DistroPackage {
		return ParseDistroPackage("openssh", up+" Ubuntu "+rev, "Ubuntu Linux; protocol 2.0")
	}
	for _, tc := range []struct {
		name string
		pkg  *domain.DistroPackage
		cve  string
		want string
	}{
		{"Debian 12 at the regreSSHion fix", deb("2+deb12u3"), "CVE-2024-6387", domain.ApplicabilityFixedByDistro},
		{"Debian 12 after the fix", deb("2+deb12u7"), "CVE-2024-6387", domain.ApplicabilityFixedByDistro},
		{"Debian 12 one update short", deb("2+deb12u2"), "CVE-2024-6387", domain.ApplicabilityDistroUnfixed},
		{"Debian 12 release package", deb("2"), "CVE-2024-6387", domain.ApplicabilityDistroUnfixed},
		{"Debian 12 Terrapin fixed in u2", deb("2+deb12u2"), "CVE-2023-48795", domain.ApplicabilityFixedByDistro},
		{"Debian 12 CVE not in the table", deb("2+deb12u3"), "CVE-2026-123158", domain.ApplicabilityBackportPossible},
		{"Ubuntu 22.04 at the fix", ubu("8.9p1", "3ubuntu0.10"), "CVE-2024-6387", domain.ApplicabilityFixedByDistro},
		{"Ubuntu 22.04 before the fix", ubu("8.9p1", "3ubuntu0.6"), "CVE-2024-6387", domain.ApplicabilityDistroUnfixed},
		{"Ubuntu 24.04 ships with the Terrapin fix", ubu("9.6p1", "3ubuntu13"), "CVE-2023-48795", domain.ApplicabilityFixedByDistro},
		{"Raspbian is not Debian for the table", ParseDistroPackage("openssh", "9.2p1 Raspbian 2+deb12u3", ""), "CVE-2024-6387", domain.ApplicabilityBackportPossible},
		{"no revision in the banner", &domain.DistroPackage{Distro: "Debian", Release: "12", Upstream: "9.2p1", Label: "Debian 12"}, "CVE-2024-6387", domain.ApplicabilityBackportPossible},
		{"other upstream version", &domain.DistroPackage{Distro: "Debian", Release: "12", Upstream: "9.3p1", Revision: "1", Label: "Debian 12"}, "CVE-2024-6387", domain.ApplicabilityBackportPossible},
		{"release unknown", &domain.DistroPackage{Distro: "Ubuntu", Upstream: "1.18.0", Label: "Ubuntu"}, "CVE-2024-6387", domain.ApplicabilityBackportPossible},
	} {
		got, note := distroApplicability("openssh", tc.cve, tc.pkg)
		if got != tc.want {
			t.Errorf("%s: %s (%s), want %s", tc.name, got, note, tc.want)
		}
		if strings.ContainsAny(note, "\u2013\u2014") {
			t.Errorf("%s: dash in %q", tc.name, note)
		}
	}
	_, note := distroApplicability("openssh", "CVE-2024-6387", deb("2+deb12u3"))
	if note != "Fixed by distribution: Debian 12 package revision 2+deb12u3 is at or above 1:9.2p1-2+deb12u3 (DSA-5724-1)." {
		t.Errorf("fixed note: %q", note)
	}
	_, note = distroApplicability("openssh", "CVE-2026-123158", deb("2+deb12u3"))
	if !strings.HasPrefix(note, "Distribution package (Debian 12): fixes may be backported, not confirmed.") {
		t.Errorf("backport note: %q", note)
	}
}

// openSSHSnapshot mirrors the lab host 10.66.2.246 (OpenSSH 9.2p1 Debian 2+deb12u3): a KEV
// entry, regreSSHion, Terrapin and an ordinary medium CVE all match the upstream version.
func openSSHSnapshot() *DB {
	s := &Snapshot{
		Schema:      SchemaVersion,
		GeneratedAt: "2026-11-21T12:00:00Z",
		CVEs: []CVE{
			{ID: "CVE-2026-123158", CVSS: 8.1, Severity: "HIGH", KEVAdded: "2026-11-09", EPSS: 0.87, EPSSPct: 0.997, Summary: "sshd on Linux with musl libc and no PAM"},
			{ID: "CVE-2024-6387", CVSS: 8.1, Severity: "HIGH", EPSS: 0.99, EPSSPct: 0.999, Summary: "regreSSHion"},
			{ID: "CVE-2023-48795", CVSS: 5.9, Severity: "MEDIUM", EPSS: 0.93, EPSSPct: 0.998, Summary: "Terrapin"},
			{ID: "CVE-2023-51385", CVSS: 6.5, Severity: "MEDIUM", EPSS: 0.2, EPSSPct: 0.9, Summary: "ssh command injection via user names"},
		},
		Products: map[string][]Affected{"openssh": {
			{CVE: "CVE-2026-123158", Ranges: []Range{{EE: "10.6"}}},
			{CVE: "CVE-2024-6387", Ranges: []Range{{SI: "8.5p1", EE: "9.8p1"}}},
			{CVE: "CVE-2023-48795", Ranges: []Range{{EE: "9.6"}}},
			{CVE: "CVE-2023-51385", Ranges: []Range{{EE: "9.6"}}},
		}},
	}
	return New(s, "test")
}

func sshService(version string) *domain.Service {
	return &domain.Service{Port: 22, ServiceName: "ssh", Product: "OpenSSH", Version: version, VersionSource: "nmap", Banner: "protocol 2.0"}
}

// Patched Debian 12 sshd: every match goes to Backported (regreSSHion and Terrapin as fixed
// by the distribution) and none reaches the counts, the KEV badge, the CVE ids or the score.
func TestDebianPackageMatchesAreBackported(t *testing.T) {
	vs := openSSHSnapshot().Assess(sshService("9.2p1 Debian 2+deb12u3"))
	if len(vs) != 1 {
		t.Fatalf("summaries: %+v", vs)
	}
	v := vs[0]
	if v.Total != 0 || v.KEV != 0 || v.MaxCVSS != 0 || v.MaxEPSS != 0 || len(v.CVEIDs) != 0 || len(v.Top) != 0 || domain.AnyVulnFindings(vs) {
		t.Fatalf("counted a backported match: %+v", v)
	}
	if !v.DistroBackport || v.Confidence != "low" || v.Package == nil || v.Package.Label != "Debian 12" || v.BackportedCount != 4 {
		t.Fatalf("summary: %+v", v)
	}
	states := []string{}
	for _, c := range v.Backported {
		states = append(states, c.ID+"="+c.Applicability)
	}
	want := "CVE-2024-6387=fixed_by_distro,CVE-2023-48795=fixed_by_distro,CVE-2026-123158=backport_possible,CVE-2023-51385=backport_possible"
	if strings.Join(states, ",") != want {
		t.Fatalf("backported order/states:\n got %s\nwant %s", strings.Join(states, ","), want)
	}
	if !v.Backported[2].KEV {
		t.Fatal("the KEV flag of a backported ref is kept for the drawer")
	}
	for _, s := range []string{"distribution package (Debian 12, revision 2+deb12u3, version from nmap -sV)", "4 version matches are listed but not counted", "CVE-2024-6387, CVE-2023-48795"} {
		if !strings.Contains(v.ConfidenceNote, s) {
			t.Errorf("confidence note %q lacks %q", v.ConfidenceNote, s)
		}
	}
	if f := Factors(vs); len(f) != 0 {
		t.Fatalf("score factors from backported matches: %+v", f)
	}
}

// One stable update short of the regreSSHion fix: that CVE is counted, the rest stays
// backported, and the KEV entry (not in the fix table) stays out.
func TestDebianPackageBelowTheFixCounts(t *testing.T) {
	vs := openSSHSnapshot().Assess(sshService("9.2p1 Debian 2+deb12u2"))
	v := vs[0]
	if v.Total != 1 || v.CVEIDs[0] != "CVE-2024-6387" || v.KEV != 0 || v.MaxCVSS != 8.1 || v.DistroBackport || v.Confidence != "high" {
		t.Fatalf("summary: %+v", v)
	}
	if v.Top[0].Applicability != domain.ApplicabilityDistroUnfixed || !strings.Contains(v.Top[0].ApplicabilityNote, "predates the distribution fix 1:9.2p1-2+deb12u3 (DSA-5724-1)") {
		t.Fatalf("top ref: %+v", v.Top[0])
	}
	if v.BackportedCount != 3 || !strings.Contains(v.ConfidenceNote, "3 other version matches are not counted") {
		t.Fatalf("backported: %d, note %q", v.BackportedCount, v.ConfidenceNote)
	}
	var reasons []string
	for _, f := range Factors(vs) {
		reasons = append(reasons, f.Reason)
		if strings.HasPrefix(f.Reason, FactorKEV) {
			t.Fatalf("KEV factor from a backported KEV entry: %+v", f)
		}
	}
	if len(reasons) != 2 || !strings.HasPrefix(reasons[0], FactorEPSS+"CVE-2024-6387") || !strings.HasPrefix(reasons[1], FactorCVSS) {
		t.Fatalf("factors: %v", reasons)
	}
}

// The same version without a distribution revision is an upstream build: unchanged.
func TestUpstreamOpenSSHUnchanged(t *testing.T) {
	v := openSSHSnapshot().Assess(sshService("9.2p1"))[0]
	if v.Total != 4 || v.KEV != 1 || v.Package != nil || v.BackportedCount != 0 || v.Confidence != "high" {
		t.Fatalf("upstream: %+v", v)
	}
}

// Passive eol hints for a CVE the distribution fixed are dropped with the database match.
func TestAnnotateDropsHintsForBackportedCVEs(t *testing.T) {
	SetCurrent(openSSHSnapshot())
	defer SetCurrent(nil)
	svc := sshService("9.2p1 Debian 2+deb12u3")
	svc.KnownVulns = []domain.VulnHint{{ID: "CVE-2024-6387", Product: "OpenSSH", Version: svc.Version, DistroPackaged: true}}
	if f := Annotate(svc, svc.LastSeen); len(f) != 0 || len(svc.KnownVulns) != 0 {
		t.Fatalf("factors %+v, hints %+v", f, svc.KnownVulns)
	}
	// Not in the snapshot at all: the fix table alone drops it.
	SetCurrent(New(&Snapshot{Schema: SchemaVersion, Products: map[string][]Affected{}}, "empty"))
	svc = sshService("9.2p1 Debian 2+deb12u3")
	svc.KnownVulns = []domain.VulnHint{{ID: "CVE-2024-6387", Product: "OpenSSH", Version: svc.Version, DistroPackaged: true}}
	Annotate(svc, svc.LastSeen)
	if len(svc.KnownVulns) != 0 {
		t.Fatalf("hint for a distribution-fixed CVE kept: %+v", svc.KnownVulns)
	}
}
