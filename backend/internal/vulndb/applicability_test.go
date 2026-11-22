package vulndb

import (
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// nginxSnapshot mirrors the lab false positive: nginx 1.20.1 matches Rapid Reset (KEV,
// HTTP/2 only), an HTTP/2 DoS from 2019, a QUIC bug and a resolver bug with no protocol
// precondition.
func nginxSnapshot() *DB {
	s := &Snapshot{
		Schema:      SchemaVersion,
		GeneratedAt: "2026-11-21T12:00:00Z",
		CVEs: []CVE{
			{ID: "CVE-2023-44487", CVSS: 7.5, Severity: "HIGH", KEVAdded: "2023-10-10", EPSS: 0.94, EPSSPct: 0.999,
				Summary: "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly"},
			{ID: "CVE-2019-9513", CVSS: 7.5, Severity: "HIGH", EPSS: 0.8, Summary: "Some HTTP/2 implementations are vulnerable to resource loops"},
			{ID: "CVE-2024-24989", CVSS: 7.5, Severity: "HIGH", EPSS: 0.01, Summary: "When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module, undisclosed requests can cause NGINX worker processes to terminate."},
			{ID: "CVE-2021-23017", CVSS: 7.7, Severity: "HIGH", EPSS: 0.3, Summary: "A security issue in nginx resolver was identified"},
		},
		Products: map[string][]Affected{"nginx": {
			{CVE: "CVE-2023-44487", Ranges: []Range{{EE: "1.25.3"}}},
			{CVE: "CVE-2019-9513", Ranges: []Range{{SI: "1.9.5", EE: "1.21.0"}}},
			{CVE: "CVE-2024-24989", Ranges: []Range{{SI: "1.19.0", EE: "1.25.4"}}},
			{CVE: "CVE-2021-23017", Ranges: []Range{{SI: "0.6.18", EE: "1.21.0"}}},
		}},
	}
	TagRequirements(s)
	return New(s, "test")
}

func nginxService(http2 string) *domain.Service {
	svc := &domain.Service{Port: 80, ServiceName: "http", Product: "nginx", Version: "1.20.1",
		HTTP: &domain.HTTPFingerprint{Scheme: "http", ServerHeader: "nginx/1.20.1", Title: "Welcome to nginx!"}}
	if http2 != "" {
		svc.HTTP.Protocols = &domain.ProtocolSupport{HTTP2: http2, HTTP2Method: "h2c-prior-knowledge", HTTP3: domain.ProtoUnknown,
			HTTP2Evidence: "connection preface: answered HTTP/1.1 400 Bad Request instead of SETTINGS; Upgrade: h2c: not switched, answered HTTP/1.1 200 OK",
			CheckedAt:     time.Date(2026, 11, 22, 1, 12, 0, 0, time.UTC)}
	}
	return svc
}

func TestRequirementTagging(t *testing.T) {
	db := nginxSnapshot()
	want := map[string]string{"CVE-2023-44487": ReqHTTP2, "CVE-2019-9513": ReqHTTP2, "CVE-2024-24989": ReqHTTP3, "CVE-2021-23017": ""}
	for id, req := range want {
		if got := RequirementOf(db.CVE(id)); got != req {
			t.Errorf("%s requires %q, want %q", id, got, req)
		}
	}
	for desc, req := range map[string]string{
		"This issue affects NGINX Plus or NGINX Open Source configurations that use HTTP/2. When NGINX processes...": ReqHTTP2,
		"Double Free and possible RCE vulnerability in Apache HTTP Server with the HTTP/2 protocol.":                 ReqHTTP2,
		"An h2c direct connection to Apache Tomcat did not release the HTTP/1.1 processor":                           ReqHTTP2,
		"NGINX Open Source has a vulnerability in the ngx_http_v3_module module.":                                    ReqHTTP3,
		"When NGINX Open Source is configured to proxy HTTP/2 traffic by setting proxy_http_version to 2":            "",
		"Traefik forwards a plain HTTP/2 or HTTP/3 CONNECT request":                                                  "",
		"In certain proxy configurations, a denial of service in mod_proxy_http2":                                    "",
		"The QuickEdit module does not properly validate access to routes":                                           "",
		"Path traversal in Apache 2.4.49":                                                                            "",
	} {
		if got := DetectRequirement(desc); got != req {
			t.Errorf("DetectRequirement(%q) = %q, want %q", desc, got, req)
		}
	}
	// The table vetoes pattern hits that are not a precondition of the scanned service.
	if RequirementOf(&CVE{ID: "CVE-2025-49630", Requires: ReqHTTP2}) != "" {
		t.Error("explicit veto ignored")
	}
}

// HTTP/2 off: Rapid Reset and the 2019 HTTP/2 DoS are suppressed with the probe evidence,
// the KEV badge, KEV factor, CVSS/EPSS maxima and CVE id list no longer see them; the QUIC
// CVE stays as an unverified version match (Alt-Svc absence proves nothing).
func TestHTTP2DisabledSuppressesHTTP2OnlyCVEs(t *testing.T) {
	db := nginxSnapshot()
	vs := db.Assess(nginxService(domain.ProtoNo))
	if len(vs) != 1 {
		t.Fatalf("summaries: %+v", vs)
	}
	v := vs[0]
	if v.KEV != 0 || v.Total != 2 || v.SuppressedCount != 2 || len(v.Suppressed) != 2 {
		t.Fatalf("kev=%d total=%d suppressed=%d", v.KEV, v.Total, v.SuppressedCount)
	}
	for _, id := range v.CVEIDs {
		if id == "CVE-2023-44487" || id == "CVE-2019-9513" {
			t.Fatalf("suppressed %s still in CVEIDs %v", id, v.CVEIDs)
		}
	}
	sup := v.Suppressed[0]
	if sup.ID != "CVE-2023-44487" || sup.Applicability != domain.ApplicabilityNotApplicable || sup.Requires != ReqHTTP2 ||
		!strings.HasPrefix(sup.ApplicabilityNote, "Not applicable: HTTP/2 disabled (connection preface: answered HTTP/1.1 400") ||
		sup.CheckedAt == nil || !sup.KEV {
		t.Fatalf("suppressed ref: %+v", sup)
	}
	if v.MaxEPSS != 0.3 || v.MaxCVSS != 7.7 {
		t.Fatalf("maxima include suppressed CVEs: epss %.2f cvss %.1f", v.MaxEPSS, v.MaxCVSS)
	}
	if v.Unverified != 1 {
		t.Fatalf("unverified = %d, want 1 (the QUIC CVE)", v.Unverified)
	}
	for _, c := range v.Top {
		if c.ID == "CVE-2024-24989" && (c.Applicability != domain.ApplicabilityUnverified || !strings.Contains(c.ApplicabilityNote, "needs HTTP/3 (QUIC)")) {
			t.Fatalf("QUIC ref: %+v", c)
		}
		if c.ID == "CVE-2021-23017" && c.Applicability != "" {
			t.Fatalf("resolver CVE got an applicability: %+v", c)
		}
	}
	for _, f := range Factors(vs) {
		if strings.HasPrefix(f.Reason, FactorKEV) || strings.Contains(f.Reason, "44487") {
			t.Fatalf("score factor from a suppressed CVE: %+v", f)
		}
	}
}

// Unknown keeps today's behaviour (KEV counted) but labels the match unverified; yes marks
// it applicable with the evidence.
func TestHTTP2UnknownAndEnabledKeepTheMatch(t *testing.T) {
	db := nginxSnapshot()
	for _, tc := range []struct{ state, app, note string }{
		{"", domain.ApplicabilityUnverified, "Version match, unverified: needs HTTP/2, not probed on this port."},
		{domain.ProtoUnknown, domain.ApplicabilityUnverified, "Version match, unverified: needs HTTP/2; connection preface"},
		{domain.ProtoYes, domain.ApplicabilityApplicable, "HTTP/2 enabled: "},
	} {
		v := db.Assess(nginxService(tc.state))[0]
		if v.KEV != 1 || v.SuppressedCount != 0 || v.Total != 4 {
			t.Fatalf("%q: kev=%d suppressed=%d total=%d", tc.state, v.KEV, v.SuppressedCount, v.Total)
		}
		top := v.Top[0]
		if top.ID != "CVE-2023-44487" || top.Applicability != tc.app || !strings.HasPrefix(top.ApplicabilityNote, tc.note) {
			t.Fatalf("%q: top %+v", tc.state, top)
		}
		var kev bool
		for _, f := range Factors([]domain.VulnSummary{v}) {
			kev = kev || strings.HasPrefix(f.Reason, FactorKEV+"CVE-2023-44487")
		}
		if !kev {
			t.Fatalf("%q: KEV factor missing", tc.state)
		}
	}
}

// When every match is ruled out the summary stays (for the drawer) with Total 0.
func TestAllSuppressedSummary(t *testing.T) {
	s := &Snapshot{Schema: SchemaVersion, CVEs: []CVE{{ID: "CVE-2023-44487", CVSS: 7.5, Severity: "HIGH", KEVAdded: "2023-10-10"}},
		Products: map[string][]Affected{"nginx": {{CVE: "CVE-2023-44487", Ranges: []Range{{EE: "1.25.3"}}}}}}
	db := New(s, "t")
	vs := db.Assess(nginxService(domain.ProtoNo))
	if len(vs) != 1 || vs[0].Total != 0 || vs[0].KEV != 0 || vs[0].SuppressedCount != 1 || domain.AnyVulnFindings(vs) {
		t.Fatalf("all-suppressed summary: %+v", vs)
	}
	if f := Factors(vs); len(f) != 0 {
		t.Fatalf("factors from an all-suppressed summary: %+v", f)
	}
}
