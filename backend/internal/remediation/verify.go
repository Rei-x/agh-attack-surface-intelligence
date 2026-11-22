package remediation

import (
	"fmt"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
)

// SystemUser is the history author for automatic verification.
const SystemUser = "verifier"

// CheckResult says whether a ticket's issue is still on the network.
type CheckResult struct {
	// Known is false when the scan data cannot tell (host missing but not gone yet).
	Known   bool
	Present bool
	Reason  string
	// Fixed is the outcome when the issue is gone (Fixed* constants).
	Fixed string
	// Detail is the product and version seen after an upgrade ("nginx 1.30.1").
	Detail string
}

// unreachable is the outcome of a service the scanner no longer reaches. It is not proof
// of a patch: a firewall rule looks the same from the scanner.
func unreachable(reason string) CheckResult {
	return CheckResult{Known: true, Fixed: FixedServiceRemoved, Reason: reason}
}

func issueGone(reason string) CheckResult {
	return CheckResult{Known: true, Fixed: FixedIssueGone, Reason: reason}
}

// Check looks at the current inventory record of the ticket's host (nil when the host was
// deleted) and decides whether the issue is still there, and if not, why.
func Check(t *Ticket, host *domain.Host, now time.Time) CheckResult {
	if host == nil {
		return unreachable("host is no longer in the inventory, so the service is no longer reachable from the scanner")
	}
	switch host.LifecycleState {
	case domain.HostStateInactive:
		return unreachable("host no longer answers on the network: the service is no longer reachable from the scanner (the host may be off or firewalled)")
	case domain.HostStateMissing:
		return CheckResult{Known: false, Reason: "host did not answer this time; waiting for more scans"}
	}
	if t.ServiceID == "" && t.Port == 0 {
		return CheckResult{Known: true, Present: true, Reason: "host is still up"}
	}
	svc := findService(host, t)
	if svc == nil {
		return unreachable(fmt.Sprintf("service no longer reachable from the scanner: port %d/%s is gone from the inventory (it may be firewalled rather than removed)", t.Port, nonEmpty(t.Protocol, "tcp")))
	}
	if svc.State != "" && svc.State != "open" {
		return unreachable(fmt.Sprintf("service no longer reachable from the scanner: port %d/%s is %s (it may be firewalled rather than removed)", svc.Port, nonEmpty(svc.Protocol, "tcp"), svc.State))
	}
	cp := *svc
	if cp.HostIP == "" {
		cp.HostIP = host.IP
	}
	eol.Annotate(&cp, now)
	seen := strings.TrimSpace(cp.Product + " " + cp.Version)
	switch t.Kind {
	case KindAdminPanel:
		if !cp.IsAdminPanel {
			return issueGone("admin panel is no longer detected; the service still answers")
		}
	case KindStaging:
		if !cp.IsStagingEnv {
			return issueGone("service no longer looks like a test instance")
		}
	case KindEOL:
		product := issueKeyPart(t.IssueKey, 1)
		still := false
		for _, o := range cp.Outdated {
			if product == "" || strings.EqualFold(o.Product, product) {
				still = true
			}
		}
		if !still {
			return versionOutcome(&cp, product, "is no longer end of life", "end-of-life check", seen)
		}
	case KindKnownVuln:
		id := issueKeyPart(t.IssueKey, 1)
		still := false
		for _, v := range cp.KnownVulns {
			if strings.EqualFold(v.ID, id) {
				still = true
			}
		}
		if !still {
			return versionOutcome(&cp, eol.VulnProduct(id), "is outside the range affected by "+id, id+" match", seen)
		}
	case KindCleartextAdmin:
		if _, ok := CleartextAdmin(cp.Port, cp.ServiceName); !ok {
			return issueGone("port no longer answers as a cleartext login protocol" + seenSuffix(seen))
		}
	}
	return CheckResult{Known: true, Present: true, Reason: "still open" + seenSuffix(seen)}
}

// versionOutcome tells an upgrade (the product still answers with a version that no
// longer matches) from a version that simply is not visible any more (banner hidden,
// product replaced): only the first is reported as upgraded.
func versionOutcome(svc *domain.Service, product, fixedText, checkName, seen string) CheckResult {
	if product != "" {
		if v, ok := eol.VersionOf(svc, product); ok {
			name := displayProduct(product)
			detail := name + " " + shortVersion(v)
			return CheckResult{Known: true, Fixed: FixedUpgraded, Detail: detail, Reason: "upgraded to " + detail + ", which " + fixedText}
		}
	}
	what := "the version"
	if product != "" {
		what = "the " + displayProduct(product) + " version"
	}
	return issueGone(what + " is no longer visible to the scanner, so the " + checkName + " no longer applies" + seenSuffix(seen) + "; confirm the upgrade with the owner")
}

// displayProduct maps a lowercased product from an issue key ("apache httpd") back to its
// table name ("Apache httpd").
func displayProduct(product string) string {
	if p := eol.Table().LookupProduct(product); p != nil {
		return p.Name
	}
	return product
}

func seenSuffix(seen string) string {
	if seen == "" {
		return ""
	}
	return " (now " + seen + ")"
}

func findService(host *domain.Host, t *Ticket) *domain.Service {
	for i := range host.Services {
		if t.ServiceID != "" && host.Services[i].ID == t.ServiceID {
			return &host.Services[i]
		}
	}
	proto := nonEmpty(t.Protocol, "tcp")
	for i := range host.Services {
		s := &host.Services[i]
		if s.Port == t.Port && strings.EqualFold(nonEmpty(s.Protocol, "tcp"), proto) {
			return s
		}
	}
	return nil
}

func issueKeyPart(key string, i int) string {
	parts := strings.Split(key, ":")
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// Outcome is what verification did to one ticket.
type Outcome struct {
	TicketID string `json:"ticket_id"`
	Action   string `json:"action"` // verified_fixed, reopened, overdue
	Reason   string `json:"reason"`
	// FixedReason is the outcome of a verified fix (Fixed* constants).
	FixedReason string `json:"fixed_reason,omitempty"`
}

// Verify applies one scan's result to the tickets (in place). lookup returns the current
// host record (nil when deleted) and ok=false when the record could not be read (the
// ticket is then left alone). Active tickets whose issue is gone become fixed with
// scanID as evidence and the outcome the scan saw; tickets past due get the overdue flag;
// verified fixes that come back are reopened. Dates in history notes are written in loc.
func Verify(tickets []Ticket, lookup func(hostID string) (*domain.Host, bool), scanID string, now time.Time, loc *time.Location) []Outcome {
	type entry struct {
		h  *domain.Host
		ok bool
	}
	if loc == nil {
		loc = locale.Location("")
	}
	var out []Outcome
	cache := map[string]entry{}
	for i := range tickets {
		t := &tickets[i]
		if t.Status == StatusAcceptedRisk {
			continue
		}
		e, cached := cache[t.HostID]
		if !cached {
			e.h, e.ok = lookup(t.HostID)
			cache[t.HostID] = e
		}
		if !e.ok {
			continue
		}
		res := Check(t, e.h, now)
		if !res.Known {
			if t.Active() {
				t.LastCheckedAt, t.LastCheckScan, t.LastCheckNote = timePtr(now), scanID, res.Reason
				out = append(out, markOverdue(t, now, loc)...)
			}
			continue
		}
		if t.Status == StatusFixed {
			// Only a fix the scanner verified is reopened automatically; a manual "fixed"
			// on a host the scan still sees as open is the analyst's call.
			if res.Present && t.Verified {
				note := "issue is back: " + res.Reason
				if err := t.SetStatus(StatusReopened, SystemUser, note, scanID, now); err == nil {
					out = append(out, Outcome{TicketID: t.ID, Action: "reopened", Reason: res.Reason})
				}
			}
			continue
		}
		t.LastCheckedAt, t.LastCheckScan, t.LastCheckNote = timePtr(now), scanID, res.Reason
		if !res.Present {
			if err := t.MarkFixed(res, scanID, now); err == nil {
				out = append(out, Outcome{TicketID: t.ID, Action: "verified_fixed", Reason: res.Reason, FixedReason: t.FixedReason})
			}
			continue
		}
		out = append(out, markOverdue(t, now, loc)...)
	}
	return out
}

func markOverdue(t *Ticket, now time.Time, loc *time.Location) []Outcome {
	if !t.PastDue(now) || t.Overdue {
		return nil
	}
	t.Overdue = true
	t.UpdatedAt = now
	t.History = append(t.History, HistoryEntry{At: now, By: SystemUser, Action: "overdue", Note: "still present after the due date " + locale.DueDay(*t.DueAt, loc)})
	return []Outcome{{TicketID: t.ID, Action: "overdue", Reason: "still present after the due date"}}
}

// inferFixedReason recovers the outcome of a fix verified by an older version (no
// FixedReason stored) from the verification note it wrote.
func inferFixedReason(note string) (string, string) {
	n := strings.ToLower(note)
	switch {
	case strings.Contains(n, "host is no longer in the inventory"),
		strings.Contains(n, "host no longer answers"),
		strings.Contains(n, "is no longer in the inventory"),
		strings.HasPrefix(n, "port ") && (strings.HasSuffix(n, " closed") || strings.HasSuffix(n, " filtered")),
		strings.Contains(n, "no longer reachable"):
		return FixedServiceRemoved, ""
	case strings.Contains(n, "no longer end of life"), strings.Contains(n, "no longer matches the version"):
		// "version is no longer end of life (now nginx 1.30.1)": the version was visible.
		if i := strings.LastIndex(note, "(now "); i >= 0 && strings.HasSuffix(note, ")") {
			now := strings.TrimSpace(note[i+len("(now ") : len(note)-1])
			if strings.ContainsAny(now, "0123456789") {
				return FixedUpgraded, shortProductVersion(now)
			}
		}
		return FixedIssueGone, ""
	}
	return FixedIssueGone, ""
}

// shortProductVersion trims "nginx 1.30.1 (Ubuntu)" to "nginx 1.30.1".
func shortProductVersion(s string) string {
	fields := strings.Fields(s)
	for i, f := range fields {
		if strings.ContainsAny(f[:1], "0123456789") {
			return strings.Join(append(fields[:i:i], shortVersion(f)), " ")
		}
	}
	return s
}
