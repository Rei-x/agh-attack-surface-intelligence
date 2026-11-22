package defectdojo

import (
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/locale"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Severities of the change findings, in one place. internal/remediation gives a ticket for
// the same condition the same severity, so the ticket due date (severity -> SLA days) and
// the SLA DefectDojo computes for the finding agree.
const (
	SeverityAdminPanel  = "Medium"
	SeverityStaging     = "Low"
	SeverityPassiveHint = "Medium" // version-only CVE hint (internal/eol known vulns)
	SeverityNewService  = "Low"
)

// cleartextOrUnauth are exposures that hand over credentials or data without any
// authentication; they are High in DefectDojo (the same band as the Dzięcioł score).
var cleartextOrUnauth = map[string]bool{
	"Telnet": true, "TELNET": true, "FTP": true, "VNC": true, "Docker API": true, "Redis": true,
	"MongoDB": true, "Elasticsearch": true, "Memcached": true, "CouchDB": true,
}

// ExposureSeverity is the severity of a risky exposure (label from ingest.RiskyExposure).
func ExposureSeverity(label string) string {
	if cleartextOrUnauth[label] {
		return "High"
	}
	return "Medium"
}

// EOLSeverity: an end-of-life branch is Medium, Low for a distribution build (fixes may
// be backported).
func EOLSeverity(o domain.OutdatedComponent) string {
	if o.DistroPackaged {
		return "Low"
	}
	return "Medium"
}

// FindingDate is the "date" of a change finding: the local calendar day (instance default
// timezone, Europe/Warsaw) the service was first seen. DefectDojo's SLA runs from this day and
// ticket due dates are computed from the same day, so both agree. A service first seen at
// 00:39 Warsaw time belongs to that day, not to the previous UTC day.
func FindingDate(firstSeen, fallback time.Time) string {
	if firstSeen.IsZero() {
		firstSeen = fallback
	}
	return locale.Date(firstSeen, locale.Location(""))
}
