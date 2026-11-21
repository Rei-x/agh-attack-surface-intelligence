package domain

// OutdatedComponent says that an identified product version belongs to a release branch
// past its end of life, according to the offline table in internal/eol (no network lookup).
// It is derived from the stored product/version/HTTP evidence, so it is recomputed on read
// and never persisted on its own.
type OutdatedComponent struct {
	Product         string `json:"product"`                    // display name, e.g. "nginx", "PHP"
	Version         string `json:"version"`                    // version as observed
	Branch          string `json:"branch"`                     // matched release branch, e.g. "1.14"
	EOLDate         string `json:"eol_date"`                   // YYYY-MM-DD
	DaysSinceEOL    int    `json:"days_since_eol"`             // at evaluation time
	LatestInBranch  string `json:"latest_in_branch,omitempty"` // last release of that branch
	SupportedBranch string `json:"supported_branch,omitempty"` // newest supported branch (upgrade target)
	Via             string `json:"via"`                        // where the version came from (nmap, http-server-header, x-powered-by, technology)
	DistroPackaged  bool   `json:"distro_packaged,omitempty"`  // distro build (Ubuntu/Debian/RHEL...): fixes may be backported
	Label           string `json:"label"`                      // short badge text, e.g. "nginx 1.14 – branch EOL since 2019-04"
	Evidence        string `json:"evidence"`                   // full explanation with source and data date
	Source          string `json:"source"`                     // citation URL of the EOL date
	DataAsOf        string `json:"data_as_of"`                 // date the EOL table was curated
}

// VulnHint is a passive, version-only hint at a well-known critical CVE. Nothing was sent
// to the service to confirm it; distro builds may carry a backported fix.
type VulnHint struct {
	ID             string   `json:"id"` // CVE id
	Name           string   `json:"name"`
	Product        string   `json:"product"`
	Version        string   `json:"version"`
	Affected       string   `json:"affected"` // human-readable affected range
	DistroPackaged bool     `json:"distro_packaged,omitempty"`
	Evidence       string   `json:"evidence"`
	References     []string `json:"references"`
}
