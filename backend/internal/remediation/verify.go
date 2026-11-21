package remediation

import (
	"fmt"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
)

// SystemUser is the history author for automatic verification.
const SystemUser = "verifier"

// CheckResult says whether a ticket's issue is still on the network.
type CheckResult struct {
	// Known is false when the scan data cannot tell (host missing but not gone yet).
	Known   bool
	Present bool
	Reason  string
}

// Check looks at the current inventory record of the ticket's host (nil when the host was
// deleted) and decides whether the issue is still there.
func Check(t *Ticket, host *domain.Host, now time.Time) CheckResult {
	if host == nil {
		return CheckResult{Known: true, Present: false, Reason: "host is no longer in the inventory"}
	}
	switch host.LifecycleState {
	case domain.HostStateInactive:
		return CheckResult{Known: true, Present: false, Reason: "host no longer answers on the network"}
	case domain.HostStateMissing:
		return CheckResult{Known: false, Reason: "host did not answer this time; waiting for more scans"}
	}
	if t.ServiceID == "" && t.Port == 0 {
		return CheckResult{Known: true, Present: true, Reason: "host is still up"}
	}
	svc := findService(host, t)
	if svc == nil {
		return CheckResult{Known: true, Present: false, Reason: fmt.Sprintf("port %d is no longer in the inventory", t.Port)}
	}
	if svc.State != "" && svc.State != "open" {
		return CheckResult{Known: true, Present: false, Reason: fmt.Sprintf("port %d/%s is %s", svc.Port, nonEmpty(svc.Protocol, "tcp"), svc.State)}
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
			return CheckResult{Known: true, Reason: "admin panel is no longer detected"}
		}
	case KindStaging:
		if !cp.IsStagingEnv {
			return CheckResult{Known: true, Reason: "service no longer looks like a test instance"}
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
			return CheckResult{Known: true, Reason: "version is no longer end of life" + seenSuffix(seen)}
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
			return CheckResult{Known: true, Reason: id + " no longer matches the version" + seenSuffix(seen)}
		}
	case KindCleartextAdmin:
		if _, ok := CleartextAdmin(cp.Port, cp.ServiceName); !ok {
			return CheckResult{Known: true, Reason: "port no longer answers as a cleartext login protocol"}
		}
	}
	return CheckResult{Known: true, Present: true, Reason: "still open" + seenSuffix(seen)}
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
}

// Verify applies one scan's result to the tickets (in place). lookup returns the current
// host record (nil when deleted) and ok=false when the record could not be read (the
// ticket is then left alone). Active tickets whose issue is gone become fixed with
// scanID as evidence; tickets past due get the overdue flag; verified fixes that come back
// are reopened.
func Verify(tickets []Ticket, lookup func(hostID string) (*domain.Host, bool), scanID string, now time.Time) []Outcome {
	type entry struct {
		h  *domain.Host
		ok bool
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
				out = append(out, markOverdue(t, now)...)
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
			if err := t.SetStatus(StatusFixed, SystemUser, res.Reason, scanID, now); err == nil {
				out = append(out, Outcome{TicketID: t.ID, Action: "verified_fixed", Reason: res.Reason})
			}
			continue
		}
		out = append(out, markOverdue(t, now)...)
	}
	return out
}

func markOverdue(t *Ticket, now time.Time) []Outcome {
	if !t.PastDue(now) || t.Overdue {
		return nil
	}
	t.Overdue = true
	t.UpdatedAt = now
	t.History = append(t.History, HistoryEntry{At: now, By: SystemUser, Action: "overdue", Note: "still present after the due date " + t.DueAt.Format("2006-01-02")})
	return []Outcome{{TicketID: t.ID, Action: "overdue", Reason: "still present after the due date"}}
}
