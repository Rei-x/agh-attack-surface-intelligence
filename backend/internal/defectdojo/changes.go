package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// Actionable change findings ("Dzięcioł changes: <profile>").
//
// The raw Nmap test lists every open port. This second test answers the questions an
// operator actually asks after a periodic scan: what risky thing is exposed, who put it up
// (owner from the CIDR rules), is it running something past end of life, what is new, what
// disappeared. It is a snapshot of the profile's current actionable state, reimported after
// every completed run with close_old_findings=true:
//
//   - a condition that still holds produces the same finding again (same title, description
//     and unique_id_from_tool), so DefectDojo leaves it untouched: no duplicates, and an
//     analyst's notes, JIRA links or risk acceptance on it stay;
//   - a condition that is gone (port closed, nginx upgraded, host back) is absent from the
//     next reimport, so DefectDojo mitigates it with the date: the audit trail of "it was
//     fixed on ...".
//
// Items an analyst triaged in Dzięcioł (accepted risk / false positive) stay in the payload
// with their Triage attached; after the reimport SyncTriage sets the matching DefectDojo
// state (risk_accepted / false_p, with the reason and expiry as a note) and reverts it when
// the decision is withdrawn or expires. Without close_old_findings fixed items would stay
// active forever and the test would only grow.
//
// DefectDojo matches reimported Generic Findings by hash_code (title + description) on a
// default install, not by unique_id_from_tool, so titles and descriptions here contain only
// stable facts (no "last seen", scores or "N days ago"); unique_id_from_tool is still set,
// stable, for instances configured to deduplicate by it.

const (
	// ChangesTestPrefix titles the per-profile change test.
	ChangesTestPrefix = "Dzięcioł changes"
	// newServiceWindow: a service first seen this recently (after the baseline) is "new".
	newServiceWindow = 7 * 24 * time.Hour
	// goneHostWindow: hosts gone longer than this drop out (decommissioned long ago).
	goneHostWindow = 30 * 24 * time.Hour
)

// Change finding kinds (also DefectDojo tags).
const (
	KindExposure  = "risky-exposure"
	KindAdmin     = "admin-panel"
	KindStaging   = "staging"
	KindEOL       = "eol"
	KindKnownVuln = "known-vuln"
	KindNew       = "new-service"
	KindHostGone  = "host-gone"
)

// ChangesTestTitle is the stable DefectDojo test title for a profile's change findings.
func ChangesTestTitle(profileName string) string {
	profileName = strings.TrimSpace(profileName)
	if profileName == "" {
		return ChangesTestPrefix
	}
	return ChangesTestPrefix + ": " + profileName
}

// ChangeFinding is one actionable finding of the change test.
type ChangeFinding struct {
	Kind      string `json:"-"`
	Owner     string `json:"-"`
	HostID    string `json:"-"`
	ServiceID string `json:"-"`
	// Triage is the analyst decision in force (accepted risk / false positive), nil when the
	// finding is active. SyncTriage mirrors it into DefectDojo.
	Triage *domain.TriageInfo `json:"-"`
	genericFinding
}

// BuildChangeFindings derives the actionable findings for hosts (already limited to the
// profile scope, services loaded) at now. Hosts or services with an active accepted-risk /
// false-positive decision keep their findings with Triage set (a host decision covers its
// services). The result is sorted by unique id (stable payload).
func BuildChangeFindings(hosts []domain.Host, now time.Time) []ChangeFinding {
	baseline := time.Time{}
	for _, h := range hosts {
		if !h.FirstSeen.IsZero() && (baseline.IsZero() || h.FirstSeen.Before(baseline)) {
			baseline = h.FirstSeen
		}
	}
	var out []ChangeFinding
	for i := range hosts {
		h := &hosts[i]
		var hostTriage *domain.TriageInfo
		if h.Triage.IsSuppressing(now) {
			hostTriage = h.Triage
		}
		if h.LifecycleState == domain.HostStateMissing || h.LifecycleState == domain.HostStateInactive {
			if !h.LastSeen.IsZero() && now.Sub(h.LastSeen) <= goneHostWindow {
				f := hostGoneFinding(h)
				f.Triage = hostTriage
				out = append(out, f)
			}
			continue // its services are stale; their findings close with the host
		}
		for j := range h.Services {
			s := h.Services[j]
			if s.State != "" && s.State != "open" {
				continue
			}
			triage := hostTriage
			if s.Triage.IsSuppressing(now) {
				triage = s.Triage
			}
			if s.HostIP == "" {
				s.HostIP = h.IP
			}
			eol.Annotate(&s, now)
			for _, f := range serviceFindings(h, &s, baseline, now) {
				f.ServiceID, f.Triage = s.ID, triage
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UniqueIDFromTool < out[j].UniqueIDFromTool })
	return out
}

func serviceFindings(h *domain.Host, s *domain.Service, baseline, now time.Time) []ChangeFinding {
	proto := nonEmpty(s.Protocol, "tcp")
	where := fmt.Sprintf("%s:%d/%s", s.HostIP, s.Port, proto)
	var out []ChangeFinding
	add := func(kind, idSuffix, title, severity, evidence string, mod func(*genericFinding)) {
		f := newFinding(h, kind, title, severity, serviceDescription(h, s, kind, evidence))
		f.UniqueIDFromTool = UniqueID(s.HostIP, s.Port, proto, "dz-change:"+kind+idSuffix)
		f.VulnIDFromTool = kind
		f.Date = dateOf(s.FirstSeen, now)
		// No finding.service here: DefectDojo's close_old_findings only closes findings whose
		// service matches the reimport's (unset) service, so setting it would keep fixed
		// items open forever.
		f.Endpoints = []genericEndpoint{{Host: s.HostIP, Port: s.Port, Protocol: endpointProtocol(s)}}
		f.ComponentName, f.ComponentVersion = s.HostIP, fmt.Sprintf("%d/%s", s.Port, proto)
		if mod != nil {
			mod(&f.genericFinding)
		}
		out = append(out, f)
	}

	if label, risky := ingest.RiskyExposure(s.Port, s.ServiceName); risky {
		add(KindExposure, "", fmt.Sprintf("Risky service exposed: %s (%s) on %s", label, s.ServiceName, where), exposureSeverity(label),
			fmt.Sprintf("Port %d/%s (%s) is reachable from the scanning network. Remote access, file sharing and database services should not be exposed without a reason.", s.Port, proto, label),
			func(g *genericFinding) {
				g.Mitigation = "Check with the owner whether the service is needed; if not, turn it off or restrict access with a firewall/VPN."
			})
	}
	if s.IsAdminPanel {
		add(KindAdmin, "", fmt.Sprintf("Admin panel exposed: %s on %s", adminName(s), where), "Medium",
			"Admin panel / management console detected: "+adminEvidence(s)+".",
			func(g *genericFinding) {
				g.Mitigation = "A management panel should not be reachable from the whole network: restrict access (VPN, allowlist) and enforce strong authentication."
			})
	}
	if s.IsStagingEnv {
		add(KindStaging, "", fmt.Sprintf("Test/staging environment exposed on %s", where), "Low",
			"The service looks like a development/test environment (staging, dev, debug). Such instances often have weaker configuration and test data.",
			func(g *genericFinding) {
				g.Mitigation = "Confirm with the owner whether the instance is needed; remove it or put it behind a VPN."
			})
	}
	for _, o := range s.Outdated {
		sev := "Medium"
		if o.DistroPackaged {
			sev = "Low"
		}
		o := o
		add(KindEOL, ":"+strings.ToLower(o.Product)+":"+o.Branch,
			fmt.Sprintf("%s %s: branch %s EOL since %s, on %s", o.Product, versionShort(o.Version), o.Branch, o.EOLDate, where), sev,
			stableEOLEvidence(o),
			func(g *genericFinding) {
				g.ComponentName, g.ComponentVersion = o.Product, versionShort(o.Version)
				g.References = o.Source
				g.Mitigation = "Upgrade to a supported branch"
				if o.SupportedBranch != "" {
					g.Mitigation += " (" + o.Product + " " + o.SupportedBranch + ")"
				}
				g.Mitigation += "; if this is a distro package, check whether the OS release itself is still supported."
			})
	}
	for _, v := range s.KnownVulns {
		v := v
		add(KindKnownVuln, ":"+v.ID,
			fmt.Sprintf("[passive hint] %s: %s %s on %s", v.ID, v.Product, versionShort(v.Version), where), "Medium",
			v.Evidence,
			func(g *genericFinding) {
				g.ComponentName, g.ComponentVersion = v.Product, versionShort(v.Version)
				g.References = strings.Join(v.References, "\n")
				g.Mitigation = "Verify the package version on the host; upgrade if the fix is not installed."
			})
	}
	if len(out) == 0 && isNew(s.FirstSeen, baseline, now) {
		add(KindNew, "", fmt.Sprintf("New service: %s on %s", nonEmpty(strings.TrimSpace(s.ServiceName+" "+s.Product), "tcp"), where), "Low",
			"The service appeared after the first scan of this scope (first seen: "+s.FirstSeen.UTC().Format("2006-01-02 15:04 UTC")+"). Who started it, and is it needed?",
			nil)
	}
	return out
}

func hostGoneFinding(h *domain.Host) ChangeFinding {
	last := h.LastSeen.UTC().Format("2006-01-02")
	title := fmt.Sprintf("Host gone from the network: %s (last seen %s)", h.IP, last)
	var b strings.Builder
	writeHostLines(&b, h)
	fmt.Fprintf(&b, "\n**Evidence:** the host stopped responding in consecutive scans (last response %s). Decommissioned on purpose or an outage? Update the inventory or check with the owner.\n", h.LastSeen.UTC().Format("2006-01-02 15:04 UTC"))
	f := newFinding(h, KindHostGone, title, "Info", b.String())
	f.UniqueIDFromTool = UniqueID(h.IP, 0, "", "dz-change:"+KindHostGone)
	f.VulnIDFromTool = KindHostGone
	f.Date = last
	f.ComponentName = h.IP
	f.Endpoints = []genericEndpoint{{Host: h.IP}}
	return f
}

func newFinding(h *domain.Host, kind, title, severity, description string) ChangeFinding {
	if h.Owner != "" {
		title += " [owner: " + h.Owner + "]"
	}
	tags := []string{"dzieciol", kind}
	if h.Owner != "" {
		tags = append(tags, "owner:"+tagSlug(h.Owner))
	}
	for _, t := range h.Tags {
		if s := tagSlug(t); s != "" {
			tags = append(tags, s)
		}
	}
	return ChangeFinding{Kind: kind, Owner: h.Owner, HostID: h.ID, genericFinding: genericFinding{
		Title:       title,
		Description: description,
		Severity:    severity,
		Active:      true,
		Tags:        tags,
	}}
}

func serviceDescription(h *domain.Host, s *domain.Service, kind, evidence string) string {
	var b strings.Builder
	writeHostLines(&b, h)
	// Product/version only where they are the point: nmap identification can improve
	// between runs ("postgresql" -> "postgresql PostgreSQL DB"), and every wording change
	// is a new hash, i.e. a closed + re-created finding in DefectDojo.
	svc := s.ServiceName
	if kind == KindEOL || kind == KindKnownVuln {
		svc = strings.TrimSpace(svc + " " + s.Product + " " + versionShort(s.Version))
	}
	fmt.Fprintf(&b, "- **Service:** `%d/%s` %s\n", s.Port, nonEmpty(s.Protocol, "tcp"), svc)
	if !s.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "- **First seen:** %s\n", s.FirstSeen.UTC().Format("2006-01-02 15:04 UTC"))
	}
	fmt.Fprintf(&b, "\n**Evidence:** %s\n", evidence)
	return b.String()
}

// writeHostLines renders the ownership block shared by all findings.
func writeHostLines(b *strings.Builder, h *domain.Host) {
	b.WriteString("Detected passively by Dzięcioł (periodic discovery scan).\n\n")
	fmt.Fprintf(b, "- **Host:** `%s`", h.IP)
	if h.Hostname != "" {
		fmt.Fprintf(b, " (%s)", h.Hostname)
	}
	b.WriteString("\n")
	if h.Owner != "" {
		fmt.Fprintf(b, "- **Owner (CIDR rule):** %s\n", h.Owner)
	} else {
		b.WriteString("- **Owner:** none. Add a CIDR rule (Admin → Tag rules) so it is clear who manages this\n")
	}
	if len(h.Tags) > 0 {
		tags := append([]string(nil), h.Tags...)
		sort.Strings(tags)
		fmt.Fprintf(b, "- **Tags:** %s\n", strings.Join(tags, ", "))
	}
	if h.Environment != "" && h.Environment != "unknown" {
		fmt.Fprintf(b, "- **Environment:** %s\n", h.Environment)
	}
	if !h.FirstSeen.IsZero() {
		fmt.Fprintf(b, "- **Host first seen:** %s\n", h.FirstSeen.UTC().Format("2006-01-02 15:04 UTC"))
	}
}

// stableEOLEvidence is the EOL explanation without the age ("N years ago"), which would
// change the DefectDojo hash over time.
func stableEOLEvidence(o domain.OutdatedComponent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s belongs to branch %s, whose support ended on %s.", o.Product, versionShort(o.Version), o.Branch, o.EOLDate)
	if o.LatestInBranch != "" {
		fmt.Fprintf(&b, " Latest release in the branch: %s.", o.LatestInBranch)
	}
	if o.SupportedBranch != "" {
		fmt.Fprintf(&b, " Supported branch: %s.", o.SupportedBranch)
	}
	fmt.Fprintf(&b, " Version from: %s.", o.Via)
	if o.DistroPackaged {
		b.WriteString(" Distro build: fixes may be backported, but the upstream branch is unsupported.")
	}
	fmt.Fprintf(&b, " Source: %s (offline table as of %s).", o.Source, o.DataAsOf)
	return b.String()
}

func adminName(s *domain.Service) string {
	for _, t := range s.Technologies {
		if t.Category == "admin_panel" && t.Name != "Admin Panel / Management Console" {
			return t.Name
		}
	}
	return nonEmpty(s.Product, s.ServiceName)
}

func adminEvidence(s *domain.Service) string {
	var names []string
	for _, t := range s.Technologies {
		if t.Category == "admin_panel" {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "admin panel signature"
	}
	return strings.Join(names, ", ")
}

func endpointProtocol(s *domain.Service) string {
	if s.HTTP != nil && s.HTTP.Scheme != "" {
		return s.HTTP.Scheme
	}
	return ""
}

func isNew(firstSeen, baseline, now time.Time) bool {
	if firstSeen.IsZero() || baseline.IsZero() {
		return false
	}
	// Everything found by the first scan of the scope is the baseline, not news.
	return firstSeen.Sub(baseline) > time.Hour && now.Sub(firstSeen) <= newServiceWindow
}

// versionShort drops distro suffixes after the first space ("1.18.0 (Ubuntu)" -> "1.18.0").
func versionShort(v string) string {
	if i := strings.IndexByte(strings.TrimSpace(v), ' '); i > 0 {
		return strings.TrimSpace(v)[:i]
	}
	return strings.TrimSpace(v)
}

func dateOf(t, fallback time.Time) string {
	if t.IsZero() {
		t = fallback
	}
	return t.UTC().Format("2006-01-02")
}

func tagSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '@', r == '-', r == '_', r == ':':
			b.WriteRune(r)
		case r == ' ' || r == '/':
			b.WriteRune('-')
		}
	}
	return b.String()
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// ImportChangeFindings reimports the change findings as a "Generic Findings Import" into the
// test named testTitle with close_old_findings=true (see the package comment above for why).
// An empty list is sent too: it closes everything that was resolved since the last run.
func (c *Client) ImportChangeFindings(ctx context.Context, cfg *domain.DefectDojoConfig, engagementID int, testTitle, runLabel string, findings []ChangeFinding) (*ImportResult, error) {
	if cfg == nil || strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("defectdojo URL is not configured")
	}
	ic, err := c.resolveContext(ctx, cfg, engagementID)
	if err != nil {
		return nil, err
	}
	doc := struct {
		Findings []genericFinding `json:"findings"`
	}{Findings: make([]genericFinding, 0, len(findings))}
	for _, f := range findings {
		doc.Findings = append(doc.Findings, f.genericFinding)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	res, err := c.reimport(ctx, cfg, ic, "Generic Findings Import", testTitle, runLabel, "dzieciol-changes.json", raw, true)
	if err != nil {
		return nil, err
	}
	out := &ImportResult{
		TestID:       res.Test,
		EngagementID: res.EngagementID,
		ProductID:    res.ProductID,
		ScanType:     "Generic Findings Import",
		Message:      fmt.Sprintf("%d change findings sent to DefectDojo test %q", len(findings), testTitle),
	}
	if res.Test > 0 {
		out.ExternalID = strconv.Itoa(res.Test)
		out.ExternalURL = fmt.Sprintf("%s/test/%d", baseURL(cfg.URL), res.Test)
	}
	return out, nil
}
