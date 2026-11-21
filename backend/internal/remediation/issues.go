package remediation

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
)

// Issue is one thing on a service the owner should fix.
type Issue struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
	Action   string `json:"action"`
	Advice   string `json:"advice"` // what to do, one sentence
	Severity string `json:"severity"`
	DueDays  int    `json:"due_days"`
}

// cleartextAdmin maps ports / service names of management protocols that send credentials
// in clear text.
var cleartextPorts = map[int]string{21: "FTP", 23: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}
var cleartextNames = map[string]string{"ftp": "FTP", "telnet": "Telnet", "exec": "rexec", "login": "rlogin", "shell": "rsh"}

// CleartextAdmin returns the protocol label when the service is a cleartext management
// protocol.
func CleartextAdmin(port int, serviceName string) (string, bool) {
	if l, ok := cleartextNames[strings.ToLower(serviceName)]; ok {
		return l, true
	}
	if l, ok := cleartextPorts[port]; ok && (serviceName == "" || strings.EqualFold(serviceName, "unknown") || strings.EqualFold(serviceName, strings.ToLower(l))) {
		return l, true
	}
	return "", false
}

// ServiceIssues lists the issues of an open service, most urgent first. svc is annotated
// with EOL data in place.
func ServiceIssues(svc *domain.Service, now time.Time) []Issue {
	if svc == nil {
		return nil
	}
	eol.Annotate(svc, now)
	where := fmt.Sprintf("%s:%d/%s", svc.HostIP, svc.Port, nonEmpty(svc.Protocol, "tcp"))
	var out []Issue
	for _, v := range svc.KnownVulns {
		ev := fmt.Sprintf("Version-only hint: %s %s is in the range affected by %s (%s). Nothing was sent to the service to confirm it.", v.Product, v.Version, v.ID, v.Affected)
		if v.DistroPackaged {
			ev += " Distribution build: the fix may be backported, check the package version."
		}
		out = append(out, Issue{
			Kind:     KindKnownVuln,
			Key:      KindKnownVuln + ":" + v.ID,
			Title:    fmt.Sprintf("%s %s may be affected by %s (%s)", v.Product, shortVersion(v.Version), v.ID, v.Name),
			Evidence: ev,
			Action:   ActionPatch,
			Advice:   "Install the vendor fix (or the distribution update that carries it), or take the service off the network.",
			Severity: "high",
			DueDays:  7,
		})
	}
	for _, o := range svc.Outdated {
		advice := "Upgrade to a supported release"
		if o.SupportedBranch != "" {
			advice += " (" + o.Product + " " + o.SupportedBranch + " or newer)"
		}
		advice += ", or remove the service if nobody needs it."
		out = append(out, Issue{
			Kind:     KindEOL,
			Key:      KindEOL + ":" + strings.ToLower(o.Product) + ":" + o.Branch,
			Title:    fmt.Sprintf("%s %s is end of life since %s", o.Product, shortVersion(o.Version), o.EOLDate),
			Evidence: eolEvidence(o),
			Action:   ActionPatch,
			Advice:   advice,
			Severity: "medium",
			DueDays:  30,
		})
	}
	if label, ok := CleartextAdmin(svc.Port, svc.ServiceName); ok {
		out = append(out, Issue{
			Kind:     KindCleartextAdmin,
			Key:      KindCleartextAdmin + ":" + strings.ToLower(label),
			Title:    fmt.Sprintf("%s (cleartext login) open on %s", label, where),
			Evidence: fmt.Sprintf("Port %d answers as %s. Passwords sent over it can be read by anyone on the path.", svc.Port, label),
			Action:   ActionRemove,
			Advice:   fmt.Sprintf("Turn off %s and use an encrypted alternative (SSH, SFTP).", label),
			Severity: "high",
			DueDays:  14,
		})
	} else if label, ok := ingest.RiskyExposure(svc.Port, svc.ServiceName); ok {
		out = append(out, Issue{
			Kind:     KindExposure,
			Key:      KindExposure + ":" + strings.ToLower(label),
			Title:    fmt.Sprintf("%s reachable on %s", label, where),
			Evidence: fmt.Sprintf("Port %d/%s (%s) answers from the scanning network.", svc.Port, nonEmpty(svc.Protocol, "tcp"), nonEmpty(svc.ServiceName, label)),
			Action:   ActionRestrict,
			Advice:   "Close the port, or allow it only from the networks that need it (firewall, VPN).",
			Severity: "medium",
			DueDays:  14,
		})
	}
	if svc.IsAdminPanel {
		name := adminName(svc)
		ev := "Admin login or management console detected"
		if svc.HTTP != nil && svc.HTTP.URL != "" {
			ev += " at " + svc.HTTP.URL
		}
		if svc.HTTP != nil && svc.HTTP.Title != "" {
			ev += fmt.Sprintf(" (page title %q)", svc.HTTP.Title)
		}
		out = append(out, Issue{
			Kind:     KindAdminPanel,
			Key:      KindAdminPanel,
			Title:    fmt.Sprintf("%s exposed on %s", name, where),
			Evidence: ev + ".",
			Action:   ActionRestrict,
			Advice:   "Allow the admin panel only from VPN or an allowlist, or remove it from this network.",
			Severity: "medium",
			DueDays:  14,
		})
	}
	if svc.IsStagingEnv {
		out = append(out, Issue{
			Kind:     KindStaging,
			Key:      KindStaging,
			Title:    fmt.Sprintf("Test or staging instance exposed on %s", where),
			Evidence: "The service looks like a development or staging instance (name, title or headers).",
			Action:   ActionRemove,
			Advice:   "Remove the instance if it is not needed, or put it behind VPN.",
			Severity: "low",
			DueDays:  30,
		})
	}
	return out
}

// GenericIssue is the fallback when the service has no specific issue (the analyst still
// wants to ask the owner about it).
func GenericIssue(svc *domain.Service, host *domain.Host) Issue {
	if svc == nil {
		return Issue{
			Kind: KindOther, Key: KindOther, Title: "Host " + host.IP + " needs review",
			Evidence: "Seen on the network by CBI AGH monitoring.",
			Action:   ActionRestrict, Advice: "Confirm the host is needed and patched, or remove it.",
			Severity: "low", DueDays: 30,
		}
	}
	what := strings.TrimSpace(strings.Join([]string{svc.ServiceName, svc.Product, svc.Version}, " "))
	return Issue{
		Kind:     KindOther,
		Key:      KindOther,
		Title:    fmt.Sprintf("Service %s on %s:%d needs review", nonEmpty(what, "unknown"), svc.HostIP, svc.Port),
		Evidence: fmt.Sprintf("Port %d/%s is open (%s).", svc.Port, nonEmpty(svc.Protocol, "tcp"), nonEmpty(what, "unidentified service")),
		Action:   ActionRestrict,
		Advice:   "Confirm the service is needed and patched; otherwise close the port.",
		Severity: "low",
		DueDays:  30,
	}
}

func adminName(s *domain.Service) string {
	generic := func(n string) bool {
		l := strings.ToLower(n)
		return n == "" || strings.Contains(l, "admin panel") || strings.Contains(l, "management console")
	}
	for _, t := range s.Technologies {
		if t.Category == "admin_panel" && !generic(t.Name) {
			return t.Name
		}
	}
	for _, t := range s.Technologies {
		if t.Confidence >= 50 && !generic(t.Name) && t.Category != "server" && t.Category != "framework" {
			return t.Name + " admin panel"
		}
	}
	return "Admin panel"
}

func shortVersion(v string) string {
	if i := strings.IndexAny(v, " (-+~"); i > 0 {
		return v[:i]
	}
	return v
}

var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// ExtractEmail returns the first email address found in the texts ("" when none).
func ExtractEmail(texts ...string) string {
	for _, t := range texts {
		if m := emailRE.FindString(t); m != "" {
			return m
		}
	}
	return ""
}

func eolEvidence(o domain.OutdatedComponent) string {
	ev := fmt.Sprintf("%s %s seen via %s. Branch %s stopped getting security fixes on %s.", o.Product, o.Version, o.Via, o.Branch, o.EOLDate)
	if o.DistroPackaged {
		ev += " Distribution build: fixes may be backported, but the upstream branch is unsupported."
	}
	if o.Source != "" {
		ev += " Source: " + o.Source
	}
	return ev
}
