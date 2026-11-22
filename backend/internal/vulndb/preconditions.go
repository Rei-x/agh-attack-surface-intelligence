package vulndb

import (
	"regexp"
	"sort"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Protocol preconditions. A version match says the code is there; for some CVEs the
// vulnerable code only runs when a protocol is enabled (Rapid Reset needs HTTP/2, the nginx
// QUIC bugs need HTTP/3). The snapshot tags those CVEs (CVE.Requires) and the scan records
// whether the service speaks the protocol (domain.ProtocolSupport), so a match on a server
// with HTTP/2 off is shown as "not applicable" instead of headlining the host.
const (
	ReqHTTP2 = "http2"
	ReqHTTP3 = "http3"
)

// RequirementLabels names the preconditions in UI text.
var RequirementLabels = map[string]string{ReqHTTP2: "HTTP/2", ReqHTTP3: "HTTP/3 (QUIC)"}

// Description patterns, deliberately conservative: each one says the flaw is in (or only
// reachable through) the server's own HTTP/2 or HTTP/3 handling. Anything about proxying to
// an HTTP/2 backend, forwarding h2c upgrades, or "HTTP/2 or HTTP/3" is excluded and left to
// the explicit table.
var (
	reqPatterns = []struct {
		req string
		re  *regexp.Regexp
	}{
		{ReqHTTP2, regexp.MustCompile(`(?i)configurations? that uses? HTTP/2\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)configured to use HTTP/2\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\bthe HTTP/2 protocol (allows|is)\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\bHTTP/2 (server )?implementations?\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\bwhen (HTTP/2|h2|mod_http2) (is|was) enabled\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\bwith the HTTP/2 protocol\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\b(HTTP/2 module|mod_http2|ngx_http_v2_module)\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\b(an?|specially crafted|crafted|malicious(ly constructed)?|fuzzed) HTTP/2 (requests?|streams?|frames?|connections?)\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\b(opening|processing|handling|during) (an? |the )?HTTP/2 (requests?|streams?|connections?|session)\b`)},
		{ReqHTTP2, regexp.MustCompile(`(?i)\b(an? )?h2c (direct )?connections?\b`)},
		{ReqHTTP3, regexp.MustCompile(`(?i)\bHTTP/3 QUIC module\b`)},
		{ReqHTTP3, regexp.MustCompile(`(?i)configurations? that uses? HTTP/3\b`)},
		{ReqHTTP3, regexp.MustCompile(`(?i)configured to use (the )?HTTP/3\b`)},
		{ReqHTTP3, regexp.MustCompile(`(?i)\b(ngx_http_v3_module\b|HTTP/3 \(QUIC\)|HTTP/3 entrypoints?\b)`)},
	}
	reqExclusions = regexp.MustCompile(`(?i)proxy_http_version|mod_proxy_http2|HTTP/2 or HTTP/3|HTTP/3 or HTTP/2|Upgrade: h2c|h2c token|backend HTTP/2`)
)

// explicitRequirements overrides the description patterns: CVEs whose precondition is
// known from the advisories (NVD descriptions are often too short to say), and "" for a
// pattern hit that is not a precondition of the listening service. Keep it small and cite
// the reason when adding a "".
var explicitRequirements = map[string]string{
	// The HTTP/2 DoS family (VU#605641, 2019) and Rapid Reset (2023): protocol-level.
	"CVE-2019-9511": ReqHTTP2, "CVE-2019-9512": ReqHTTP2, "CVE-2019-9513": ReqHTTP2, "CVE-2019-9514": ReqHTTP2,
	"CVE-2019-9515": ReqHTTP2, "CVE-2019-9516": ReqHTTP2, "CVE-2019-9517": ReqHTTP2, "CVE-2019-9518": ReqHTTP2,
	"CVE-2023-44487": ReqHTTP2,
	// HTTP/2 CONTINUATION flood (VU#421644).
	"CVE-2024-27316": ReqHTTP2, "CVE-2024-27983": ReqHTTP2, "CVE-2024-28182": ReqHTTP2,
	// nginx ngx_http_v2_module.
	"CVE-2018-16843": ReqHTTP2, "CVE-2018-16844": ReqHTTP2, "CVE-2026-123007": ReqHTTP2, "CVE-2026-123633": ReqHTTP2,
	// Apache httpd mod_http2 (httpd security advisories list them under mod_http2).
	"CVE-2016-1546": ReqHTTP2, "CVE-2016-4979": ReqHTTP2, "CVE-2016-8740": ReqHTTP2, "CVE-2017-7659": ReqHTTP2,
	"CVE-2017-9789": ReqHTTP2, "CVE-2018-1302": ReqHTTP2, "CVE-2018-1333": ReqHTTP2, "CVE-2018-11763": ReqHTTP2,
	"CVE-2018-17189": ReqHTTP2, "CVE-2019-0196": ReqHTTP2, "CVE-2019-0197": ReqHTTP2, "CVE-2019-10081": ReqHTTP2,
	"CVE-2019-10082": ReqHTTP2, "CVE-2020-9490": ReqHTTP2, "CVE-2020-11993": ReqHTTP2, "CVE-2021-31618": ReqHTTP2,
	"CVE-2021-33193": ReqHTTP2, "CVE-2021-41524": ReqHTTP2, "CVE-2023-43622": ReqHTTP2, "CVE-2023-45802": ReqHTTP2,
	"CVE-2024-36387": ReqHTTP2,
	// Apache Tomcat HTTP/2 (Http2UpgradeHandler, h2c).
	"CVE-2016-6817": ReqHTTP2, "CVE-2017-5650": ReqHTTP2, "CVE-2017-7675": ReqHTTP2, "CVE-2019-0199": ReqHTTP2,
	"CVE-2019-10072": ReqHTTP2, "CVE-2020-11996": ReqHTTP2, "CVE-2020-13934": ReqHTTP2, "CVE-2020-13943": ReqHTTP2,
	"CVE-2021-25122": ReqHTTP2, "CVE-2024-24549": ReqHTTP2, "CVE-2024-34750": ReqHTTP2, "CVE-2024-52317": ReqHTTP2,
	"CVE-2025-53506": ReqHTTP2,
	// Jetty HTTP/2 (bundled in Jenkins; HTTP/2 off unless --http2Port).
	"CVE-2022-2048": ReqHTTP2,
	// Traefik HTTP/2 handling.
	"CVE-2022-39271": ReqHTTP2, "CVE-2023-54365": ReqHTTP2,
	// nginx HTTP/3 QUIC module (not built or enabled by default).
	"CVE-2024-24989": ReqHTTP3, "CVE-2024-24990": ReqHTTP3, "CVE-2024-31079": ReqHTTP3, "CVE-2024-32760": ReqHTTP3,
	"CVE-2024-34161": ReqHTTP3, "CVE-2024-35200": ReqHTTP3,
	// Traefik HTTP/3 early data.
	"CVE-2024-39321": ReqHTTP3,

	// Not a precondition of the scanned service:
	"CVE-2025-49630": "", // mod_proxy_http2: httpd proxying to an HTTP/2 backend
	"CVE-2026-42926": "", // nginx proxy_http_version 2: backend side
	"CVE-2026-88008": "", // Traefik forwards Upgrade: h2c to backends
	"CVE-2020-11080": "", // nghttp2 inside MySQL: not the MySQL protocol port
}

// DetectRequirement returns the protocol precondition a CVE description states ("" if none).
func DetectRequirement(desc string) string {
	if desc == "" || reqExclusions.MatchString(desc) {
		return ""
	}
	found := ""
	for _, p := range reqPatterns {
		if p.re.MatchString(desc) {
			if found != "" && found != p.req {
				return "" // mentions both: not a single-protocol precondition
			}
			found = p.req
		}
	}
	return found
}

// RequirementOf returns the precondition of a CVE: the explicit table first, then the tag
// stored in the snapshot (so a snapshot built before tagging still gets the table).
func RequirementOf(c *CVE) string {
	if c == nil {
		return ""
	}
	if r, ok := explicitRequirements[c.ID]; ok {
		return r
	}
	return c.Requires
}

// TagStats summarises a TagRequirements run.
type TagStats struct {
	ByRequirement map[string]int `json:"by_requirement"`
	FromTable     int            `json:"from_table"`
	Examples      []string       `json:"examples"`
}

// TagRequirements sets CVE.Requires on every record from its (stored, possibly shortened)
// description and the explicit table. A tag found earlier from the full NVD description is
// kept unless the table says otherwise. It does not touch GeneratedAt: no data is fetched.
func TagRequirements(s *Snapshot) TagStats {
	st := TagStats{ByRequirement: map[string]int{}}
	for i := range s.CVEs {
		c := &s.CVEs[i]
		if r := DetectRequirement(c.Summary); r != "" {
			c.Requires = r
		}
		if r, ok := explicitRequirements[c.ID]; ok {
			if r != "" {
				st.FromTable++
			}
			c.Requires = r
		}
		if c.Requires != "" {
			st.ByRequirement[c.Requires]++
			st.Examples = append(st.Examples, c.ID+" ["+c.Requires+"] "+c.Summary)
		}
	}
	sort.Strings(st.Examples)
	return st
}

// applicabilityResult is the verdict for one CVE on one service.
type applicabilityResult struct {
	req, state, note string
	checked          time.Time
}

func (a applicabilityResult) apply(ref *domain.CVERef) {
	if a.req == "" {
		return
	}
	ref.Requires, ref.Applicability, ref.ApplicabilityNote = a.req, a.state, a.note
	if !a.checked.IsZero() {
		t := a.checked
		ref.CheckedAt = &t
	}
}

func protocolsOf(svc *domain.Service) *domain.ProtocolSupport {
	if svc == nil || svc.HTTP == nil {
		return nil
	}
	return svc.HTTP.Protocols
}

// applicability decides whether a CVE with precondition req applies to a service whose
// protocol probe result is ps. Only a definite "HTTP/2 is off" suppresses; HTTP/3 is read
// from Alt-Svc alone, so its absence never rules a CVE out.
func applicability(req string, ps *domain.ProtocolSupport) applicabilityResult {
	r := applicabilityResult{req: req}
	if req == "" {
		return r
	}
	label := RequirementLabels[req]
	if ps == nil {
		r.state, r.note = domain.ApplicabilityUnverified, "Version match, unverified: needs "+label+", not probed on this port."
		return r
	}
	r.checked = ps.CheckedAt
	state, evidence := ps.HTTP2, ps.HTTP2Evidence
	if req == ReqHTTP3 {
		state, evidence = ps.HTTP3, ps.HTTP3Evidence
	}
	switch state {
	case domain.ProtoYes:
		r.state, r.note = domain.ApplicabilityApplicable, label+" enabled: "+evidence+"."
	case domain.ProtoNo:
		r.state, r.note = domain.ApplicabilityNotApplicable, "Not applicable: "+label+" disabled ("+evidence+")."
	default:
		why := "the probe was inconclusive"
		if evidence != "" {
			why = evidence
		}
		r.state, r.note = domain.ApplicabilityUnverified, "Version match, unverified: needs "+label+"; "+why+"."
	}
	return r
}
