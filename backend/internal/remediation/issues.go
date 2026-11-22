package remediation

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/defectdojo"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
)

// Issue is one thing on a service the owner should fix.
type Issue struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
	Action   string `json:"action"`
	Advice   string `json:"advice"` // what to do, one sentence
	// Severity is the one DefectDojo gets for the same condition (internal/defectdojo), so
	// the SLA days, the ticket due date and DefectDojo's SLA agree.
	Severity string `json:"severity"`
	DueDays  int    `json:"due_days"` // SLA days of the severity
}

// cleartextPorts and cleartextNames map the ports and service names of management
// protocols that send credentials in clear text.
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

func lower(severity string) string { return strings.ToLower(severity) }

// ServiceIssues lists the issues of an open service, most urgent first, in English (the
// analyst UI and the digest). svc is annotated with EOL data in place.
func ServiceIssues(svc *domain.Service, now time.Time) []Issue {
	return ServiceIssuesIn(svc, now, locale.EN)
}

// ServiceIssuesIn is ServiceIssues with titles, evidence and advice in a notice language.
// Keys, kinds, actions and severities do not depend on the language.
func ServiceIssuesIn(svc *domain.Service, now time.Time, lang string) []Issue {
	if svc == nil {
		return nil
	}
	tx := textFor(lang)
	eol.Annotate(svc, now)
	proto := nonEmpty(svc.Protocol, "tcp")
	where := fmt.Sprintf("%s:%d/%s", svc.HostIP, svc.Port, proto)
	var out []Issue
	add := func(is Issue) {
		is.DueDays = DefaultSLA.Days(is.Severity)
		out = append(out, is)
	}
	for _, v := range svc.KnownVulns {
		add(vulnIssue(tx, v))
	}
	for _, o := range svc.Outdated {
		advice := tx.eolAdvice
		if o.SupportedBranch != "" {
			advice = fmt.Sprintf(tx.eolAdviceTo, o.Product, o.UpgradeTarget()) // nginx: "1.30 (stable)", not mainline 1.31
		}
		add(Issue{
			Kind:     KindEOL,
			Key:      KindEOL + ":" + strings.ToLower(o.Product) + ":" + o.Branch,
			Title:    fmt.Sprintf(tx.eolTitle, o.Product, shortVersion(o.Version), o.EOLDate),
			Evidence: eolEvidence(tx, o),
			Action:   ActionPatch,
			Advice:   advice,
			Severity: lower(defectdojo.EOLSeverity(o)),
		})
	}
	if label, ok := CleartextAdmin(svc.Port, svc.ServiceName); ok {
		// DefectDojo files it as a risky exposure when the port is a known one (Telnet, FTP:
		// High); rexec / rlogin / rsh have no DefectDojo finding and stay High.
		sev := "high"
		if dl, risky := ingest.RiskyExposure(svc.Port, svc.ServiceName); risky {
			sev = lower(defectdojo.ExposureSeverity(dl))
		}
		add(Issue{
			Kind:     KindCleartextAdmin,
			Key:      KindCleartextAdmin + ":" + strings.ToLower(label),
			Title:    fmt.Sprintf(tx.clearTitle, label, where),
			Evidence: fmt.Sprintf(tx.clearEvidence, svc.Port, label),
			Action:   ActionRemove,
			Advice:   fmt.Sprintf(tx.clearAdvice, label),
			Severity: sev,
		})
	} else if label, ok := ingest.RiskyExposure(svc.Port, svc.ServiceName); ok {
		add(Issue{
			Kind:     KindExposure,
			Key:      KindExposure + ":" + strings.ToLower(label),
			Title:    fmt.Sprintf(tx.expTitle, label, where),
			Evidence: fmt.Sprintf(tx.expEvidence, svc.Port, proto, nonEmpty(svc.ServiceName, label)),
			Action:   ActionRestrict,
			Advice:   tx.expAdvice,
			Severity: lower(defectdojo.ExposureSeverity(label)),
		})
	}
	if svc.IsAdminPanel {
		ev := tx.adminEvidence
		if svc.HTTP != nil && svc.HTTP.URL != "" {
			ev += fmt.Sprintf(tx.adminAt, svc.HTTP.URL)
		}
		if svc.HTTP != nil && svc.HTTP.Title != "" {
			ev += fmt.Sprintf(tx.adminPageTitle, svc.HTTP.Title)
		}
		add(Issue{
			Kind:     KindAdminPanel,
			Key:      KindAdminPanel,
			Title:    adminTitle(tx, svc, where),
			Evidence: ev + ".",
			Action:   ActionRestrict,
			Advice:   tx.adminAdvice,
			Severity: lower(defectdojo.SeverityAdminPanel),
		})
	}
	if svc.IsStagingEnv {
		add(Issue{
			Kind:     KindStaging,
			Key:      KindStaging,
			Title:    fmt.Sprintf(tx.stagingTitle, where),
			Evidence: tx.stagingEvidence,
			Action:   ActionRemove,
			Advice:   tx.stagingAdvice,
			Severity: lower(defectdojo.SeverityStaging),
		})
	}
	return out
}

// vulnIssue is the issue of a passive, version-only CVE hint (one the vulnerability
// database did not match itself).
func vulnIssue(tx *texts, v domain.VulnHint) Issue {
	ev := fmt.Sprintf(tx.vulnEvidence, v.Product, v.Version, v.ID, v.Affected)
	if v.DistroPackaged {
		ev += tx.vulnDistro
	}
	sev := lower(defectdojo.SeverityPassiveHint)
	return Issue{
		Kind:     KindKnownVuln,
		Key:      KindKnownVuln + ":" + v.ID,
		Title:    fmt.Sprintf(tx.vulnTitle, v.Product, shortVersion(v.Version), v.ID, tx.vulnName(v.ID, v.Name)),
		Evidence: ev,
		Action:   ActionPatch,
		Advice:   tx.vulnAdvice,
		Severity: sev,
		DueDays:  DefaultSLA.Days(sev),
	}
}

// GenericIssue is the fallback when the service has no specific issue (the analyst still
// wants to ask the owner about it), in English.
func GenericIssue(svc *domain.Service, host *domain.Host) Issue {
	return GenericIssueIn(svc, host, locale.EN)
}

// GenericIssueIn is GenericIssue in a notice language. It has no DefectDojo finding; its
// severity is Low.
func GenericIssueIn(svc *domain.Service, host *domain.Host, lang string) Issue {
	tx := textFor(lang)
	if svc == nil {
		return Issue{
			Kind: KindOther, Key: KindOther, Title: fmt.Sprintf(tx.hostTitle, host.IP),
			Evidence: tx.hostEvidence,
			Action:   ActionRestrict, Advice: tx.hostAdvice,
			Severity: "low", DueDays: DefaultSLA.Days("low"),
		}
	}
	what := strings.TrimSpace(strings.Join([]string{svc.ServiceName, svc.Product, svc.Version}, " "))
	return Issue{
		Kind:     KindOther,
		Key:      KindOther,
		Title:    fmt.Sprintf(tx.svcTitle, nonEmpty(what, tx.unknownService), svc.HostIP, svc.Port),
		Evidence: fmt.Sprintf(tx.svcEvidence, svc.Port, nonEmpty(svc.Protocol, "tcp"), nonEmpty(what, tx.unidentifiedService)),
		Action:   ActionRestrict,
		Advice:   tx.svcAdvice,
		Severity: "low",
		DueDays:  DefaultSLA.Days("low"),
	}
}

func adminTitle(tx *texts, svc *domain.Service, where string) string {
	if tx.lang == locale.EN {
		return fmt.Sprintf(tx.adminTitleNamed, adminName(svc), where)
	}
	if name := adminProduct(svc); name != "" {
		return fmt.Sprintf(tx.adminTitleNamed, name, where)
	}
	return fmt.Sprintf(tx.adminTitle, where)
}

func genericAdminName(n string) bool {
	l := strings.ToLower(n)
	return n == "" || strings.Contains(l, "admin panel") || strings.Contains(l, "management console")
}

// adminProduct is the product behind an admin panel ("phpMyAdmin", "Jenkins"), "" when
// only a generic panel was detected.
func adminProduct(s *domain.Service) string {
	for _, t := range s.Technologies {
		if t.Category == "admin_panel" && !genericAdminName(t.Name) {
			return t.Name
		}
	}
	for _, t := range s.Technologies {
		if t.Confidence >= 50 && !genericAdminName(t.Name) && t.Category != "server" && t.Category != "framework" {
			return t.Name
		}
	}
	return ""
}

func adminName(s *domain.Service) string {
	for _, t := range s.Technologies {
		if t.Category == "admin_panel" && !genericAdminName(t.Name) {
			return t.Name
		}
	}
	if name := adminProduct(s); name != "" {
		return name + " admin panel"
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

func eolEvidence(tx *texts, o domain.OutdatedComponent) string {
	ev := fmt.Sprintf(tx.eolEvidence, o.Product, o.Version, tx.viaLabel(o.Via), o.Branch, o.EOLDate)
	if o.DistroPackaged {
		ev += tx.eolDistro
	}
	if o.Source != "" {
		ev += tx.source + o.Source
	}
	return ev
}
