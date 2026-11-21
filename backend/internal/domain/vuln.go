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
	// Confidence of the version match: "high" (exact version from the service itself),
	// "medium" (version from page content / technology fingerprint, or incomplete), "low"
	// (distro build: fixes are often backported, so the match is only possible).
	Confidence     string   `json:"confidence"`
	ConfidenceNote string   `json:"confidence_note"`
	DistroBackport bool     `json:"distro_backport,omitempty"`
	Top            []CVERef `json:"top"`     // up to 3, KEV first, then EPSS, then CVSS
	CVEIDs         []string `json:"cve_ids"` // every matched CVE, same order
	DataAsOf       string   `json:"data_as_of"`
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
