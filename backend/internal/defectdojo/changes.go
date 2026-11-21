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
//   - a condition that is gone (port closed, nginx upgraded, host back, item triaged as
//     accepted risk / false positive in Dzięcioł) is absent from the next reimport, so
//     DefectDojo mitigates it with the date — the audit trail of "it was fixed on ...".
//
// Without close_old_findings fixed items would stay active forever and the test would only
// grow. The trade-off: an item suppressed in Dzięcioł shows as "mitigated" in DefectDojo
// rather than "risk accepted"; Dzięcioł stays the source of truth for that decision.
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
	Kind  string `json:"-"`
	Owner string `json:"-"`
	genericFinding
}

// BuildChangeFindings derives the actionable findings for hosts (already limited to the
// profile scope, services loaded) at now. Hosts or services with an active accepted-risk /
// false-positive decision are skipped. The result is sorted by unique id (stable payload).
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
		if h.Triage.IsSuppressing(now) {
			continue
		}
		if h.LifecycleState == domain.HostStateMissing || h.LifecycleState == domain.HostStateInactive {
			if !h.LastSeen.IsZero() && now.Sub(h.LastSeen) <= goneHostWindow {
				out = append(out, hostGoneFinding(h))
			}
			continue // its services are stale; their findings close with the host
		}
		for j := range h.Services {
			s := h.Services[j]
			if s.State != "" && s.State != "open" {
				continue
			}
			if s.Triage.IsSuppressing(now) {
				continue
			}
			if s.HostIP == "" {
				s.HostIP = h.IP
			}
			eol.Annotate(&s, now)
			out = append(out, serviceFindings(h, &s, baseline, now)...)
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
		add(KindExposure, "", fmt.Sprintf("Ryzykowna usługa wystawiona: %s (%s) na %s", label, s.ServiceName, where), "Medium",
			fmt.Sprintf("Port %d/%s (%s) jest osiągalny z sieci skanowania. Usługi zdalnego dostępu, udziałów plików i baz danych nie powinny być wystawione bez potrzeby.", s.Port, proto, label),
			func(g *genericFinding) {
				g.Mitigation = "Ustal z właścicielem, czy usługa jest potrzebna; jeśli nie — wyłącz ją albo ogranicz dostęp firewallem/VPN."
			})
	}
	if s.IsAdminPanel {
		add(KindAdmin, "", fmt.Sprintf("Panel administracyjny wystawiony: %s na %s", adminName(s), where), "Medium",
			"Wykryto panel administracyjny / konsolę zarządzania: "+adminEvidence(s)+".",
			func(g *genericFinding) {
				g.Mitigation = "Panel zarządzania nie powinien być dostępny z całej sieci: ogranicz dostęp (VPN, allowlista), wymuś silne uwierzytelnianie."
			})
	}
	if s.IsStagingEnv {
		add(KindStaging, "", fmt.Sprintf("Środowisko testowe/staging wystawione na %s", where), "Low",
			"Usługa wygląda na środowisko deweloperskie/testowe (staging, dev, debug). Takie instancje często mają słabszą konfigurację i dane testowe.",
			func(g *genericFinding) {
				g.Mitigation = "Potwierdź z właścicielem, czy instancja jest potrzebna; usuń ją albo zamknij za VPN."
			})
	}
	for _, o := range s.Outdated {
		sev := "Medium"
		if o.DistroPackaged {
			sev = "Low"
		}
		o := o
		add(KindEOL, ":"+strings.ToLower(o.Product)+":"+o.Branch,
			fmt.Sprintf("%s %s – gałąź %s EOL od %s, na %s", o.Product, versionShort(o.Version), o.Branch, o.EOLDate, where), sev,
			stableEOLEvidence(o),
			func(g *genericFinding) {
				g.ComponentName, g.ComponentVersion = o.Product, versionShort(o.Version)
				g.References = o.Source
				g.Mitigation = "Zaktualizuj do wspieranej gałęzi"
				if o.SupportedBranch != "" {
					g.Mitigation += " (" + o.Product + " " + o.SupportedBranch + ")"
				}
				g.Mitigation += "; jeśli to pakiet dystrybucji, sprawdź czy samo wydanie systemu jest jeszcze wspierane."
			})
	}
	for _, v := range s.KnownVulns {
		v := v
		add(KindKnownVuln, ":"+v.ID,
			fmt.Sprintf("[pasywna wskazówka] %s: %s %s na %s", v.ID, v.Product, versionShort(v.Version), where), "Medium",
			v.Evidence,
			func(g *genericFinding) {
				g.ComponentName, g.ComponentVersion = v.Product, versionShort(v.Version)
				g.References = strings.Join(v.References, "\n")
				g.Mitigation = "Zweryfikuj wersję pakietu na hoście; zaktualizuj, jeśli poprawka nie jest zainstalowana."
			})
	}
	if len(out) == 0 && isNew(s.FirstSeen, baseline, now) {
		add(KindNew, "", fmt.Sprintf("Nowa usługa: %s na %s", nonEmpty(strings.TrimSpace(s.ServiceName+" "+s.Product), "tcp"), where), "Low",
			"Usługa pojawiła się po pierwszym skanie tego zakresu (pierwsze wykrycie: "+s.FirstSeen.UTC().Format("2006-01-02 15:04 UTC")+"). Kto ją uruchomił i czy jest potrzebna?",
			nil)
	}
	return out
}

func hostGoneFinding(h *domain.Host) ChangeFinding {
	last := h.LastSeen.UTC().Format("2006-01-02")
	title := fmt.Sprintf("Host zniknął z sieci: %s (ostatnio widziany %s)", h.IP, last)
	var b strings.Builder
	writeHostLines(&b, h)
	fmt.Fprintf(&b, "\n**Dowód:** host przestał odpowiadać w kolejnych skanach (ostatnia odpowiedź %s). Usunięty celowo czy awaria? Zaktualizuj ewidencję albo sprawdź u właściciela.\n", h.LastSeen.UTC().Format("2006-01-02 15:04 UTC"))
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
		title += " [właściciel: " + h.Owner + "]"
	}
	tags := []string{"dzieciol", "aegis-asi", kind}
	if h.Owner != "" {
		tags = append(tags, "owner:"+tagSlug(h.Owner))
	}
	for _, t := range h.Tags {
		if s := tagSlug(t); s != "" {
			tags = append(tags, s)
		}
	}
	return ChangeFinding{Kind: kind, Owner: h.Owner, genericFinding: genericFinding{
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
	svc := strings.TrimSpace(s.ServiceName + " " + s.Product)
	if kind == KindEOL || kind == KindKnownVuln {
		svc = strings.TrimSpace(svc + " " + versionShort(s.Version))
	}
	fmt.Fprintf(&b, "- **Usługa:** `%d/%s` %s\n", s.Port, nonEmpty(s.Protocol, "tcp"), svc)
	if !s.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "- **Pierwsze wykrycie:** %s\n", s.FirstSeen.UTC().Format("2006-01-02 15:04 UTC"))
	}
	fmt.Fprintf(&b, "\n**Dowód:** %s\n", evidence)
	return b.String()
}

// writeHostLines renders the ownership block shared by all findings.
func writeHostLines(b *strings.Builder, h *domain.Host) {
	b.WriteString("Wykryte pasywnie przez Dzięcioł (AegisASI), cykliczny skan discovery.\n\n")
	fmt.Fprintf(b, "- **Host:** `%s`", h.IP)
	if h.Hostname != "" {
		fmt.Fprintf(b, " (%s)", h.Hostname)
	}
	b.WriteString("\n")
	if h.Owner != "" {
		fmt.Fprintf(b, "- **Właściciel (reguła CIDR):** %s\n", h.Owner)
	} else {
		b.WriteString("- **Właściciel:** brak — dodaj regułę CIDR (Ustawienia → Reguły CIDR), żeby wiadomo było, kto tym zarządza\n")
	}
	if len(h.Tags) > 0 {
		tags := append([]string(nil), h.Tags...)
		sort.Strings(tags)
		fmt.Fprintf(b, "- **Tagi:** %s\n", strings.Join(tags, ", "))
	}
	if h.Environment != "" && h.Environment != "unknown" {
		fmt.Fprintf(b, "- **Środowisko:** %s\n", h.Environment)
	}
	if !h.FirstSeen.IsZero() {
		fmt.Fprintf(b, "- **Host pierwszy raz widziany:** %s\n", h.FirstSeen.UTC().Format("2006-01-02 15:04 UTC"))
	}
}

// stableEOLEvidence is the EOL explanation without the age ("N lat temu"), which would
// change the DefectDojo hash over time.
func stableEOLEvidence(o domain.OutdatedComponent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s należy do gałęzi %s, której wsparcie zakończyło się %s.", o.Product, versionShort(o.Version), o.Branch, o.EOLDate)
	if o.LatestInBranch != "" {
		fmt.Fprintf(&b, " Ostatnie wydanie gałęzi: %s.", o.LatestInBranch)
	}
	if o.SupportedBranch != "" {
		fmt.Fprintf(&b, " Wspierana gałąź: %s.", o.SupportedBranch)
	}
	fmt.Fprintf(&b, " Wersja z: %s.", o.Via)
	if o.DistroPackaged {
		b.WriteString(" Build dystrybucji: poprawki mogą być backportowane, ale gałąź upstream nie jest wspierana.")
	}
	fmt.Fprintf(&b, " Źródło: %s (tabela offline z %s).", o.Source, o.DataAsOf)
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
		return "sygnatura panelu administracyjnego"
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
		ScanType:     "Generic Findings Import",
		Message:      fmt.Sprintf("%d change findings sent to DefectDojo test %q", len(findings), testTitle),
	}
	if res.Test > 0 {
		out.ExternalID = strconv.Itoa(res.Test)
		out.ExternalURL = fmt.Sprintf("%s/test/%d", baseURL(cfg.URL), res.Test)
	}
	return out, nil
}
