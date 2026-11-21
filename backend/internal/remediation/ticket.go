// Package remediation closes the loop between "we found something risky" and "the owner
// fixed it": a ticket per finding (host + service + issue), a message to the owner, a
// status flow, and automatic verification against every completed scan.
//
// Status flow:
//
//	open -> notified -> acknowledged -> fixed
//	any active status -> accepted_risk
//	fixed / accepted_risk -> reopened -> notified ...
//
// "Overdue" is not a status: it is a flag set by verification when an active ticket is
// still present after its due date.
package remediation

import (
	"fmt"
	"strings"
	"time"
)

// Ticket statuses.
const (
	StatusOpen         = "open"
	StatusNotified     = "notified"
	StatusAcknowledged = "acknowledged"
	StatusFixed        = "fixed"
	StatusReopened     = "reopened"
	StatusAcceptedRisk = "accepted_risk"
)

// AllStatuses lists every status in board order.
var AllStatuses = []string{StatusOpen, StatusNotified, StatusAcknowledged, StatusReopened, StatusFixed, StatusAcceptedRisk}

// transitions lists the allowed manual or automatic moves.
var transitions = map[string][]string{
	StatusOpen:         {StatusNotified, StatusAcknowledged, StatusFixed, StatusAcceptedRisk},
	StatusNotified:     {StatusNotified, StatusAcknowledged, StatusFixed, StatusAcceptedRisk},
	StatusAcknowledged: {StatusNotified, StatusFixed, StatusAcceptedRisk},
	StatusReopened:     {StatusNotified, StatusAcknowledged, StatusFixed, StatusAcceptedRisk},
	StatusFixed:        {StatusReopened},
	StatusAcceptedRisk: {StatusReopened},
}

// ValidStatus reports whether s is a known status.
func ValidStatus(s string) bool {
	_, ok := transitions[s]
	return ok
}

// IsActive reports whether a ticket in status s still waits for a fix.
func IsActive(s string) bool {
	return s != StatusFixed && s != StatusAcceptedRisk
}

// CanTransition reports whether a ticket may move from one status to another.
func CanTransition(from, to string) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Issue kinds (the same names DefectDojo change findings use as tags, plus cleartext-admin).
const (
	KindKnownVuln      = "known-vuln"
	KindEOL            = "eol"
	KindAdminPanel     = "admin-panel"
	KindCleartextAdmin = "cleartext-admin"
	KindExposure       = "risky-exposure"
	KindStaging        = "staging"
	KindOther          = "other"
)

// Requested owner actions.
const (
	ActionPatch    = "patch"
	ActionRemove   = "remove"
	ActionRestrict = "restrict"
)

// HistoryEntry is one change of a ticket.
type HistoryEntry struct {
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	Action string    `json:"action"` // created, notified, status, verified_fixed, still_present, overdue, reopened
	From   string    `json:"from,omitempty"`
	To     string    `json:"to,omitempty"`
	Note   string    `json:"note,omitempty"`
	ScanID string    `json:"scan_id,omitempty"`
}

// Ticket is one remediation request for a finding on a host or service.
type Ticket struct {
	ID        string `json:"id"`
	HostID    string `json:"host_id"`
	HostIP    string `json:"host_ip"`
	Hostname  string `json:"hostname,omitempty"`
	ServiceID string `json:"service_id,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Service   string `json:"service,omitempty"` // service name, product and version as seen

	Kind     string `json:"kind"`
	IssueKey string `json:"issue_key"` // stable: kind plus product/branch or CVE id
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
	Action   string `json:"action"` // patch, remove, restrict
	Severity string `json:"severity"`

	Owner      string `json:"owner,omitempty"`
	OwnerEmail string `json:"owner_email,omitempty"`

	Status   string     `json:"status"`
	Overdue  bool       `json:"overdue"`
	Verified bool       `json:"verified"` // fixed status was confirmed by a scan
	DueAt    *time.Time `json:"due_at,omitempty"`

	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
	Channel string `json:"channel,omitempty"` // email, webhook, manual (last delivery)

	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	NotifiedAt     *time.Time `json:"notified_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	FixedAt        *time.Time `json:"fixed_at,omitempty"`
	FixedScanID    string     `json:"fixed_scan_id,omitempty"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	LastCheckScan  string     `json:"last_check_scan_id,omitempty"`
	LastCheckNote  string     `json:"last_check_note,omitempty"`

	// DefectDojoUniqueID is the unique_id_from_tool of the matching DefectDojo change
	// finding, so a DefectDojo sync can find it.
	DefectDojoUniqueID string `json:"defectdojo_unique_id,omitempty"`

	History []HistoryEntry `json:"history"`
}

// Active reports whether the ticket still waits for a fix.
func (t *Ticket) Active() bool { return IsActive(t.Status) }

// Where returns "ip:port/proto" (or the IP for host level tickets).
func (t *Ticket) Where() string {
	if t.Port == 0 {
		return t.HostIP
	}
	return fmt.Sprintf("%s:%d/%s", t.HostIP, t.Port, nonEmpty(t.Protocol, "tcp"))
}

// SetStatus moves the ticket to status to, records history and stamps the status time.
// It refuses moves the flow does not allow.
func (t *Ticket) SetStatus(to, by, note, scanID string, now time.Time) error {
	to = strings.TrimSpace(to)
	if !ValidStatus(to) {
		return fmt.Errorf("unknown status %q", to)
	}
	from := t.Status
	if !CanTransition(from, to) {
		return fmt.Errorf("cannot move a ticket from %s to %s", from, to)
	}
	t.Status = to
	t.UpdatedAt = now
	switch to {
	case StatusNotified:
		t.NotifiedAt = timePtr(now)
	case StatusAcknowledged:
		t.AcknowledgedAt = timePtr(now)
	case StatusFixed:
		t.FixedAt = timePtr(now)
		t.FixedScanID = scanID
		t.Verified = scanID != ""
		t.Overdue = false
	case StatusAcceptedRisk:
		t.Overdue = false
	case StatusReopened:
		t.FixedAt = nil
		t.FixedScanID = ""
		t.Verified = false
	}
	action := "status"
	switch {
	case to == StatusFixed && scanID != "":
		action = "verified_fixed"
	case to == StatusReopened:
		action = "reopened"
	case to == StatusNotified:
		action = "notified"
	}
	t.History = append(t.History, HistoryEntry{At: now, By: by, Action: action, From: from, To: to, Note: note, ScanID: scanID})
	return nil
}

// AgeDays is the number of whole days since the ticket was created.
func (t *Ticket) AgeDays(now time.Time) int {
	if t.CreatedAt.IsZero() {
		return 0
	}
	return int(now.Sub(t.CreatedAt).Hours() / 24)
}

// PastDue reports whether an active ticket passed its due date.
func (t *Ticket) PastDue(now time.Time) bool {
	return t.Active() && t.DueAt != nil && now.After(*t.DueAt)
}

func timePtr(t time.Time) *time.Time { return &t }

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
