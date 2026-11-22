package defectdojo

import (
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

// FindingDate is the "date" of a change finding: the day the service was first seen, in
// UTC as it has always been sent (changing it would not re-date existing findings).
// DefectDojo's SLA runs from this day.
func FindingDate(firstSeen, fallback time.Time) string {
	if firstSeen.IsZero() {
		firstSeen = fallback
	}
	return firstSeen.UTC().Format("2006-01-02")
}
