package defectdojo

import (
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

// nginx 1.20.1 on a plain-HTTP port: Rapid Reset (KEV, HTTP/2 only) plus a resolver CVE.
const ddRapidResetFixture = `{"schema":1,"generated_at":"2026-11-21T00:00:00Z",
 "cves":[
  {"id":"CVE-2023-44487","s":7.5,"sev":"HIGH","k":"2023-10-10","e":0.94,"ep":0.999,"rq":"http2","d":"The HTTP/2 protocol allows a denial of service"},
  {"id":"CVE-2021-23017","s":7.7,"sev":"HIGH","e":0.3,"ep":0.9,"d":"nginx resolver off-by-one"}],
 "products":{"nginx":[{"c":"CVE-2023-44487","r":[{"ee":"1.25.3"}]},{"c":"CVE-2021-23017","r":[{"ee":"1.21.0"}]}]}}`

func rapidResetHost(http2 string) domain.Host {
	base := changesNow.Add(-10 * 24 * time.Hour)
	svc := domain.Service{ID: "s1", Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx", Version: "1.20.1",
		FirstSeen: base, LastSeen: changesNow,
		HTTP: &domain.HTTPFingerprint{Scheme: "http", ServerHeader: "nginx/1.20.1", Protocols: &domain.ProtocolSupport{
			HTTP2: http2, HTTP2Evidence: "connection preface: answered HTTP/1.1 400 Bad Request instead of SETTINGS", CheckedAt: changesNow}}}
	return domain.Host{IP: "10.66.2.246", LifecycleState: domain.HostStateActive, FirstSeen: base, LastSeen: changesNow, Services: []domain.Service{svc}}
}

func useFixture(t *testing.T, raw string) {
	t.Helper()
	snap, err := vulndb.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	vulndb.SetCurrent(vulndb.New(snap, "test"))
	t.Cleanup(func() {
		empty, _ := vulndb.Parse([]byte(`{"schema":1,"products":{}}`))
		vulndb.SetCurrent(vulndb.New(empty, "test"))
	})
}

func vulndbFinding(findings []ChangeFinding) *ChangeFinding {
	for i := range findings {
		if findings[i].Kind == KindKnownVuln && strings.Contains(findings[i].UniqueIDFromTool+findings[i].Title, "nginx") && findings[i].ComponentName == "nginx" {
			return &findings[i]
		}
	}
	return nil
}

// HTTP/2 off: the finding is no longer "Known exploited", not Critical, does not carry the
// suppressed CVE id or the KEV flag, and says why it was left out.
func TestDefectDojoHTTP2OffIsNotCriticalKEV(t *testing.T) {
	useFixture(t, ddRapidResetFixture)
	f := vulndbFinding(BuildChangeFindings([]domain.Host{rapidResetHost(domain.ProtoNo)}, changesNow))
	if f == nil {
		t.Fatal("no known-vulnerability finding for the resolver CVE")
	}
	if strings.Contains(f.Title, "KEV") || f.Severity == "Critical" || f.KnownExploited {
		t.Fatalf("suppressed KEV still drives the finding: title %q severity %s kev %v", f.Title, f.Severity, f.KnownExploited)
	}
	if f.CVE == "CVE-2023-44487" || strings.Contains(strings.Join(f.VulnerabilityIDs, ","), "44487") {
		t.Fatalf("suppressed CVE sent as a vulnerability id: %s %v", f.CVE, f.VulnerabilityIDs)
	}
	if !strings.Contains(f.Description, "Not applicable (excluded from this finding):** CVE-2023-44487") ||
		!strings.Contains(f.Description, "HTTP/2 disabled") {
		t.Fatalf("description does not explain the exclusion:\n%s", f.Description)
	}

	// Unknown keeps the current behaviour: Critical KEV.
	f = vulndbFinding(BuildChangeFindings([]domain.Host{rapidResetHost(domain.ProtoUnknown)}, changesNow))
	if f == nil || f.Severity != "Critical" || !f.KnownExploited {
		t.Fatalf("unknown HTTP/2: %+v", f)
	}
}

// Every match ruled out: no known-vulnerability finding at all (DefectDojo closes the old one).
func TestDefectDojoAllSuppressedSendsNothing(t *testing.T) {
	useFixture(t, strings.Replace(ddRapidResetFixture, `,{"c":"CVE-2021-23017","r":[{"ee":"1.21.0"}]}`, "", 1))
	if f := vulndbFinding(BuildChangeFindings([]domain.Host{rapidResetHost(domain.ProtoNo)}, changesNow)); f != nil {
		t.Fatalf("finding for a fully suppressed match: %s (%s)", f.Title, f.Severity)
	}
}
