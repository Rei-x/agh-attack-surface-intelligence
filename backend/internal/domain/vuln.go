package domain

import "time"

// VulnSummary is the known-vulnerability picture of one identified product on a service,
// derived by internal/vulndb from the offline NVD/KEV/EPSS snapshot (version-only, nothing
// is sent to the service). Recomputed on read, never stored.
type VulnSummary struct {
	Product           string  `json:"product"`
	Version           string  `json:"version"`
	Via               string  `json:"via"`           // where the version came from (nmap, http-server-header, technology...)
	CPE               string  `json:"cpe,omitempty"` // NVD vendor:product the version was matched as
	Total             int     `json:"total"`         // matched CVEs (definite + possible)
	Possible          int     `json:"possible"`      // of which only possibly affected (incomplete version)
	Critical          int     `json:"critical"`      // by CVSS severity
	High              int     `json:"high"`          //
	Medium            int     `json:"medium"`        //
	Low               int     `json:"low"`           //
	MaxCVSS           float64 `json:"max_cvss"`
	KEV               int     `json:"kev"`                  // CVEs in CISA KEV (exploited in the wild)
	Ransomware        bool    `json:"ransomware,omitempty"` // a KEV entry is known to be used by ransomware
	MaxEPSS           float64 `json:"max_epss"`             // highest EPSS probability (0..1)
	MaxEPSSPercentile float64 `json:"max_epss_percentile"`
	// Confidence of the version match: "high" (exact version from the service itself, or a
	// distribution package the fix table shows predates the fix), "medium" (version from page
	// content / technology fingerprint, or incomplete), "low" (distribution build with no
	// confirmed match: everything is in Backported).
	Confidence     string `json:"confidence"`
	ConfidenceNote string `json:"confidence_note"`
	// DistroBackport: the version is a distribution build and no match is confirmed, so every
	// CVE is in Backported and nothing is counted. Package is set for every distribution build.
	DistroBackport bool           `json:"distro_backport,omitempty"`
	Package        *DistroPackage `json:"package,omitempty"`
	Top            []CVERef       `json:"top"`     // up to 3, KEV first, then EPSS, then CVSS
	CVEIDs         []string       `json:"cve_ids"` // every matched CVE, same order
	DataAsOf       string         `json:"data_as_of"`
	// Suppressed are version matches the scan ruled out: their protocol precondition (HTTP/2)
	// is off on this port. Shown greyed with the reason; excluded from every count above, the
	// KEV badge, the score, the query terms and DefectDojo.
	Suppressed      []CVERef `json:"suppressed,omitempty"`
	SuppressedCount int      `json:"suppressed_count,omitempty"` // len(Suppressed), kept in slim lists
	// Unverified counts the CVEs above whose precondition could not be checked (protocol not
	// probed or probe inconclusive): plain version matches.
	Unverified int `json:"unverified,omitempty"`
	// Backported are version matches on a distribution package (Package) that the
	// distribution may have fixed without changing the upstream version
	// (ApplicabilityBackportPossible), or that the fix table shows it did
	// (ApplicabilityFixedByDistro). Listed greyed with the reason; like Suppressed they are
	// excluded from every count above, the KEV badge, the score, the query terms and DefectDojo.
	Backported      []CVERef `json:"backported,omitempty"`
	BackportedCount int      `json:"backported_count,omitempty"` // len(Backported), kept in slim lists
}

// DistroPackage is the distribution package a service version belongs to, read from the
// banner by vulndb.ParseDistroPackage: "9.2p1 Debian 2+deb12u3" is Debian 12 (bookworm),
// package revision 2+deb12u3 of upstream 9.2p1.
type DistroPackage struct {
	Distro   string `json:"distro,omitempty"`   // Debian, Ubuntu, Raspbian, RHEL, CentOS, Rocky Linux, Amazon Linux...; "" when only a build marker (-fips) was seen
	Release  string `json:"release,omitempty"`  // 12, 22.04, 7, 2023
	Codename string `json:"codename,omitempty"` // bookworm, jammy, el7
	Revision string `json:"revision,omitempty"` // package revision as the banner shows it: 2+deb12u3, 3ubuntu0.10, 21.el7
	Upstream string `json:"upstream,omitempty"` // upstream version: 9.2p1
	// ReleaseInferred: the release was read from the upstream version the distribution ships
	// (OpenSSH 8.9p1 on Ubuntu is 22.04), not named by the banner itself.
	ReleaseInferred bool   `json:"release_inferred,omitempty"`
	Label           string `json:"label"` // "Debian 12", "Ubuntu 22.04", "CentOS", "" when unknown
}

// Applicability of a protocol-dependent CVE on one service (CVERef.Applicability).
const (
	ApplicabilityApplicable    = "applicable"     // the protocol is on
	ApplicabilityNotApplicable = "not_applicable" // the protocol is off: suppressed
	ApplicabilityUnverified    = "unverified"     // version match only, protocol not checked

	// Distribution packages (VulnSummary.Package).
	ApplicabilityBackportPossible = "backport_possible" // the distribution may have backported the fix: listed in Backported, not counted
	ApplicabilityFixedByDistro    = "fixed_by_distro"   // the package revision is at or above the distribution fix: listed in Backported
	ApplicabilityDistroUnfixed    = "distro_unfixed"    // the package revision predates the distribution fix: counted
)

// HasFindings reports whether any CVE is left after suppression.
func (v VulnSummary) HasFindings() bool { return v.Total > 0 }

// AnyVulnFindings reports whether a service has at least one applicable CVE match.
func AnyVulnFindings(vulns []VulnSummary) bool {
	for _, v := range vulns {
		if v.Total > 0 {
			return true
		}
	}
	return false
}

// CVERef is one CVE as shown on a service.
type CVERef struct {
	ID             string  `json:"id"`
	CVSS           float64 `json:"cvss"`
	Severity       string  `json:"severity"`
	EPSS           float64 `json:"epss"`
	EPSSPercentile float64 `json:"epss_percentile"`
	KEV            bool    `json:"kev"`
	KEVDateAdded   string  `json:"kev_date_added,omitempty"`
	Summary        string  `json:"summary"`
	Possible       bool    `json:"possible,omitempty"`
	Range          string  `json:"range,omitempty"`
	URL            string  `json:"url"`
	// Requires is the protocol the vulnerable code needs (http2, http3); Applicability says
	// whether this service has it, with the probe evidence and time. On a distribution
	// package Applicability says whether the distribution fixed it (backport_possible,
	// fixed_by_distro, distro_unfixed), with the reason in ApplicabilityNote.
	Requires          string     `json:"requires,omitempty"`
	Applicability     string     `json:"applicability,omitempty"`
	ApplicabilityNote string     `json:"applicability_note,omitempty"`
	CheckedAt         *time.Time `json:"checked_at,omitempty"`
}

// VerifiedFinding is the result of one safe verification check (internal/verify) run
// against a service: a "possible" exposure turned into a confirmed one, with the request and
// a redacted response snippet as evidence.
type VerifiedFinding struct {
	CheckID      string    `json:"check_id"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"` // info, low, medium, high, critical
	ServiceID    string    `json:"service_id"`
	HostIP       string    `json:"host_ip"`
	Port         int       `json:"port"`
	Request      string    `json:"request"`  // what was sent (secrets redacted)
	Evidence     string    `json:"evidence"` // response snippet (secrets redacted)
	Remediation  string    `json:"remediation"`
	References   []string  `json:"references,omitempty"`
	DefaultCreds bool      `json:"default_creds,omitempty"` // confirmed with a well-known default credential
	CheckedAt    time.Time `json:"checked_at"`
	ScanRunID    string    `json:"scan_run_id,omitempty"`
}
