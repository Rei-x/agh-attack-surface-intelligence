package remediation

import (
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
)

// SLA is the number of days an owner gets to fix an issue, by severity.
type SLA map[string]int

// DefaultSLA is DefectDojo's default SLA configuration ("Default" SLA, System Settings >
// SLA Configuration): Critical 7, High 30, Medium 90, Low 120 days. Tickets take their
// severity from the DefectDojo mapping (internal/defectdojo/severity.go), so the ticket due
// date, the "patch by" date of the notice and DefectDojo's SLA expiry are the same day.
// An instance with a different DefectDojo SLA configuration sets the same numbers in the
// delivery settings (outbound.Settings.SLADays); this table is the only other place.
var DefaultSLA = SLA{"critical": 7, "high": 30, "medium": 90, "low": 120}

// EffectiveSLA is DefaultSLA with the configured overrides on top.
func EffectiveSLA(overrides map[string]int) SLA {
	out := SLA{}
	for k, v := range DefaultSLA {
		out[k] = v
	}
	for k, v := range overrides {
		if _, ok := out[k]; ok && v > 0 {
			out[k] = v
		}
	}
	return out
}

// Days is the SLA of a severity. Info and unknown severities (DefectDojo has no SLA for
// Info) get the Low value.
func (s SLA) Days(severity string) int {
	if d, ok := s[strings.ToLower(strings.TrimSpace(severity))]; ok && d > 0 {
		return d
	}
	if d := s["low"]; d > 0 {
		return d
	}
	return DefaultSLA["low"]
}

// SLAInfo explains a default due date in the notify dialog.
type SLAInfo struct {
	Severity string `json:"severity"`
	Days     int    `json:"days"`
	// Start is the day the SLA runs from: the DefectDojo finding date (the service's
	// first-seen day) when the issue has a DefectDojo finding, else the ticket's day.
	Start string `json:"start"`
	// Expires is Start plus Days: DefectDojo's SLA expiry for the finding.
	Expires string `json:"expires"`
	// FromDefectDojo is true when Start is the DefectDojo finding date.
	FromDefectDojo bool `json:"from_defectdojo"`
	// Expired reports that the SLA ran out before the ticket was opened; the due date then
	// gives the owner the full SLA from today and differs from DefectDojo's expiry.
	Expired bool `json:"expired"`
	// Due is the default due day (YYYY-MM-DD, instance timezone).
	Due string `json:"due"`
}

// DueFor computes the default due time (23:59 of the due day in loc) of an issue of
// severity. findingDate is the DefectDojo finding date ("" when the issue has no DefectDojo
// finding).
func DueFor(sla SLA, severity, findingDate string, now time.Time, loc *time.Location) (time.Time, SLAInfo) {
	info := SLAInfo{Severity: strings.ToLower(severity), Days: sla.Days(severity)}
	today := locale.Date(now, loc)
	info.Start, info.FromDefectDojo = today, false
	if findingDate != "" {
		info.Start, info.FromDefectDojo = findingDate, true
	}
	exp, err := locale.AddDays(info.Start, info.Days)
	if err != nil {
		info.Start, info.FromDefectDojo = today, false
		exp, _ = locale.AddDays(today, info.Days)
	}
	info.Expires = exp
	due, _ := locale.EndOfDay(exp, loc)
	if due.Before(now) {
		info.Expired = true
		d, _ := locale.AddDays(today, info.Days)
		due, _ = locale.EndOfDay(d, loc)
	}
	info.Due = locale.Date(due, loc)
	return due, info
}
