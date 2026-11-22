package vulndb

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Interestingness factor prefixes (registered with eol.RegisterAnnotator so a re-score
// replaces them) and their standalone weights (domain.CombineFactors). A KEV CVE that applies
// (exact upstream version, precondition not ruled out) weighs the most: it says attackers use
// the hole. A KEV match that is only possible (incomplete version) and a high EPSS weigh
// less; CVSS alone says how bad it would be, not how likely. Matches on a distribution
// package (fix possibly backported) weigh nothing: they are listed, not counted.
const (
	FactorKEV  = "Exploited in the wild (CISA KEV): "
	FactorEPSS = "High exploit probability (EPSS): "
	FactorCVSS = "Known CVEs: "

	PointsKEV          = 60
	PointsKEVPossible  = 15
	PointsEPSSHigh     = 25 // EPSS >= 0.5
	PointsEPSSMedium   = 10 // EPSS >= 0.1
	PointsCVSSCritical = 12 // CVSS >= 9
	PointsCVSSHigh     = 6  // CVSS >= 7
)

// FactorPrefixes lists the prefixes above.
var FactorPrefixes = []string{FactorKEV, FactorEPSS, FactorCVSS}

var (
	reDistro      = regexp.MustCompile(`(?i)(ubuntu|debian|\+deb|deb\d+u|centos|red ?hat|rhel|\.el[5-9]|fedora|suse|amzn|alpine|raspbian|-fips)`)
	reHeaderToken = regexp.MustCompile(`(?i)\b(apache|nginx|php|microsoft-iis|openresty)/(\d+(?:\.\d+)*[a-z]?\d*)`)
)

// Core assets versioned with the WordPress release (jQuery and plugins carry their own).
var reWPAssetVer = regexp.MustCompile(`/wp-(?:admin/load-(?:styles|scripts)\.php|includes/(?:css/dashicons|css/buttons|js/wp-emoji-release|js/wp-embed)[a-z.-]*)[^"'\s>]*[?&](?:amp;)?ver=(\d+\.\d+(?:\.\d+)?)\b`)

func hasTech(svc *domain.Service, name string) bool {
	for _, t := range svc.Technologies {
		if strings.EqualFold(t.Name, name) {
			return true
		}
	}
	return false
}

type candidate struct {
	def     *ProductDef
	version string
	via     string
}

// candidates collects product/version claims from a service, best evidence first.
func candidates(svc *domain.Service) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(def *ProductDef, version, via string) {
		if def == nil || seen[def.Key] || normalizeVersion(version) == "" {
			return
		}
		seen[def.Key] = true
		out = append(out, candidate{def: def, version: strings.TrimSpace(version), via: via})
	}
	if svc.Product != "" && svc.Version != "" {
		def, v := lookupDef(svc.Product), svc.Version
		// MariaDB answers the MySQL handshake as "5.5.5-10.6.16-MariaDB-0ubuntu...".
		if strings.Contains(strings.ToLower(v), "mariadb") {
			def, v = defByKey("mariadb"), strings.TrimPrefix(v, "5.5.5-")
		}
		add(def, v, nonEmpty(svc.VersionSource, "nmap"))
	}
	if fp := svc.HTTP; fp != nil {
		for _, m := range reHeaderToken.FindAllStringSubmatch(fp.ServerHeader, -1) {
			add(lookupDef(m[1]), m[2], "http-server-header")
		}
		for k, v := range fp.Headers {
			if strings.EqualFold(k, "X-Powered-By") {
				for _, m := range reHeaderToken.FindAllStringSubmatch(v, -1) {
					add(lookupDef(m[1]), m[2], "x-powered-by")
				}
			}
		}
	}
	for _, t := range svc.Technologies {
		if t.Version != "" {
			add(lookupDef(t.Name), t.Version, "technology")
		}
	}
	// WordPress without a generator tag (hidden, or the install page of a fresh instance)
	// still loads its core assets with ?ver=<core version>.
	if fp := svc.HTTP; fp != nil && !seen["wordpress"] && hasTech(svc, "wordpress") {
		if m := reWPAssetVer.FindStringSubmatch(fp.BodySnippet); m != nil {
			add(defByKey("wordpress"), m[1], "http-page")
		}
	}
	return out
}

// distroBuild reports whether the version evidence of this candidate names a distribution
// build. Application versions read from page content (WordPress, Drupal...) are upstream
// releases even when the web server in front of them is a Debian package.
func distroBuild(svc *domain.Service, c candidate) bool {
	switch c.via {
	case "technology", "http-page":
		return false
	case "http-server-header":
		return svc.HTTP != nil && reDistro.MatchString(svc.HTTP.ServerHeader)
	case "x-powered-by":
		if svc.HTTP != nil {
			for k, v := range svc.HTTP.Headers {
				if strings.EqualFold(k, "X-Powered-By") && reDistro.MatchString(v) {
					return true
				}
			}
		}
		return false
	}
	ctx := c.version + " " + svc.Banner
	if svc.HTTP != nil {
		ctx += " " + svc.HTTP.ServerHeader
	}
	return reDistro.MatchString(ctx)
}

var viaLabels = map[string]string{
	"nmap":               "nmap -sV",
	"cpe":                "nmap CPE",
	"banner":             "service banner",
	"http-server-header": "Server header",
	"http-page":          "page content",
	"x-powered-by":       "X-Powered-By header",
	"technology":         "technology fingerprint",
}

// Assess returns the known-vulnerability summaries of a service (nil when nothing matches).
func (d *DB) Assess(svc *domain.Service) []domain.VulnSummary {
	if svc == nil {
		return nil
	}
	var out []domain.VulnSummary
	for _, c := range candidates(svc) {
		hits := d.Lookup(c.def.Key, c.version)
		if len(hits) == 0 {
			continue
		}
		out = append(out, d.summarize(svc, c, hits))
	}
	return out
}

func (d *DB) summarize(svc *domain.Service, c candidate, hits []Hit) domain.VulnSummary {
	nv := normalizeVersion(c.version)
	pkgVersion, pkgContext := packageEvidence(svc, c)
	pkg := ParseDistroPackage(c.def.Key, pkgVersion, pkgContext)
	if pkg == nil && distroBuild(svc, c) {
		pkg = &domain.DistroPackage{Upstream: nv} // a build marker (-fips) without a distribution name
	}
	vs := domain.VulnSummary{
		Product:  c.def.Name,
		Version:  c.version,
		Via:      c.via,
		CPE:      c.def.CPEs[0],
		Package:  pkg,
		DataAsOf: dateOnly(d.snap.GeneratedAt),
	}
	ps := protocolsOf(svc)
	var fixed []string
	for _, h := range hits {
		app := applicability(RequirementOf(h.CVE), ps)
		if app.state == domain.ApplicabilityNotApplicable {
			ref := cveRef(h)
			app.apply(&ref)
			vs.Suppressed = append(vs.Suppressed, ref)
			continue
		}
		// A distribution package: the version says the upstream code was vulnerable, not
		// whether the distribution's fix is installed. Only a fix-table row can confirm the
		// package predates the fix; everything else is listed, not counted.
		distroState, distroNote := "", ""
		if pkg != nil {
			distroState, distroNote = distroApplicability(c.def.Key, h.CVE.ID, pkg)
			if distroState != domain.ApplicabilityDistroUnfixed {
				ref := cveRef(h)
				ref.Applicability, ref.ApplicabilityNote = distroState, distroNote
				vs.Backported = append(vs.Backported, ref)
				if distroState == domain.ApplicabilityFixedByDistro {
					fixed = append(fixed, h.CVE.ID)
				}
				continue
			}
		}
		if app.state == domain.ApplicabilityUnverified {
			vs.Unverified++
		}
		vs.Total++
		if h.Possible {
			vs.Possible++
		}
		switch strings.ToUpper(h.CVE.Severity) {
		case "CRITICAL":
			vs.Critical++
		case "HIGH":
			vs.High++
		case "MEDIUM":
			vs.Medium++
		case "LOW":
			vs.Low++
		}
		if h.CVE.CVSS > vs.MaxCVSS {
			vs.MaxCVSS = h.CVE.CVSS
		}
		if h.CVE.KEVAdded != "" {
			vs.KEV++
			if h.CVE.Ransomware {
				vs.Ransomware = true
			}
		}
		if h.CVE.EPSS > vs.MaxEPSS {
			vs.MaxEPSS = h.CVE.EPSS
		}
		if h.CVE.EPSSPct > vs.MaxEPSSPercentile {
			vs.MaxEPSSPercentile = h.CVE.EPSSPct
		}
		vs.CVEIDs = append(vs.CVEIDs, h.CVE.ID)
		if len(vs.Top) < 3 {
			ref := cveRef(h)
			app.apply(&ref)
			if distroState != "" && ref.Applicability == "" {
				ref.Applicability, ref.ApplicabilityNote = distroState, distroNote
			}
			vs.Top = append(vs.Top, ref)
		}
	}
	vs.SuppressedCount = len(vs.Suppressed)
	// Fixed by the distribution first: the definite answers, then the open questions.
	sort.SliceStable(vs.Backported, func(i, j int) bool {
		return vs.Backported[i].Applicability == domain.ApplicabilityFixedByDistro && vs.Backported[j].Applicability != domain.ApplicabilityFixedByDistro
	})
	vs.BackportedCount = len(vs.Backported)
	// Confidence of the version match.
	label := nonEmpty(viaLabels[c.via], c.via)
	exactParts := numericParts(nv) >= c.def.FullParts || hasSuffix(nv)
	switch {
	case pkg != nil && vs.Total == 0:
		vs.DistroBackport = true
		vs.Confidence = "low"
		vs.ConfidenceNote = fmt.Sprintf("%s %s is a distribution package (%s). %d version %s listed but not counted: %s",
			c.def.Name, c.version, packageWhere(pkg, label), vs.BackportedCount, plural(vs.BackportedCount, "match is", "matches are"), backportReason(fixed))
	case pkg != nil:
		vs.Confidence = "high"
		vs.ConfidenceNote = fmt.Sprintf("%s %s is a distribution package (%s) whose revision predates the distribution fix for %s.",
			c.def.Name, c.version, packageWhere(pkg, label), strings.Join(vs.CVEIDs, ", "))
		if n := vs.BackportedCount; n > 0 {
			vs.ConfidenceNote += fmt.Sprintf(" %d other version %s not counted: %s", n, plural(n, "match is", "matches are"), backportReason(fixed))
		}
	case !exactParts:
		vs.Confidence = "medium"
		vs.ConfidenceNote = fmt.Sprintf("Incomplete version %q (from %s): %d of %d CVEs depend on the missing patch level.", nv, label, vs.Possible, vs.Total)
	case c.via == "technology" || c.via == "http-page":
		vs.Confidence = "medium"
		vs.ConfidenceNote = fmt.Sprintf("Exact version %s from the %s (page content can be stale or spoofed).", nv, label)
	default:
		vs.Confidence = "high"
		vs.ConfidenceNote = fmt.Sprintf("Exact upstream version %s reported by the service (%s).", nv, label)
	}
	return vs
}

// packageWhere is the parenthesised detail of a distribution package note:
// "Debian 12, revision 2+deb12u3, version from nmap -sV".
func packageWhere(pkg *domain.DistroPackage, via string) string {
	var parts []string
	if pkg.Label != "" {
		parts = append(parts, pkg.Label)
	}
	if pkg.Revision != "" {
		parts = append(parts, "revision "+pkg.Revision)
	}
	return strings.Join(append(parts, "version from "+via), ", ")
}

// backportReason says why a distribution package's matches are listed but not counted.
func backportReason(fixed []string) string {
	s := "fixes may be backported, not confirmed."
	if len(fixed) > 0 {
		s += fmt.Sprintf(" Fixed by the distribution according to its security tracker: %s.", strings.Join(fixed, ", "))
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func cveRef(h Hit) domain.CVERef {
	return domain.CVERef{
		ID:             h.CVE.ID,
		CVSS:           h.CVE.CVSS,
		Severity:       h.CVE.Severity,
		EPSS:           h.CVE.EPSS,
		EPSSPercentile: h.CVE.EPSSPct,
		KEV:            h.CVE.KEVAdded != "",
		KEVDateAdded:   h.CVE.KEVAdded,
		Summary:        h.CVE.Summary,
		Possible:       h.Possible,
		Range:          h.Range,
		URL:            NVDLink(h.CVE.ID),
	}
}

// NVDLink is the public NVD page of a CVE.
func NVDLink(id string) string { return "https://nvd.nist.gov/vuln/detail/" + id }

// Annotate fills svc.Vulns from the current database and returns the score factors. Passive
// eol hints (svc.KnownVulns) whose CVE the database also matched are dropped, so the same
// CVE is neither shown nor scored twice. It is registered with eol.RegisterAnnotator.
func Annotate(svc *domain.Service, _ time.Time) []domain.InterestingnessFactor {
	if svc == nil {
		return nil
	}
	svc.Vulns = Current().Assess(svc)
	if len(svc.Vulns) == 0 && len(svc.KnownVulns) == 0 {
		return nil
	}
	if len(svc.KnownVulns) > 0 {
		covered := map[string]bool{}
		for _, v := range svc.Vulns {
			for _, id := range v.CVEIDs {
				covered[id] = true
			}
			for _, c := range v.Suppressed {
				covered[c.ID] = true // ruled out by the protocol probe: no passive hint either
			}
			for _, c := range v.Backported {
				covered[c.ID] = true // distribution package: listed there, not as a hint
			}
		}
		kept := svc.KnownVulns[:0:0]
		for _, h := range svc.KnownVulns {
			if !covered[h.ID] && !hintFixedByDistro(svc, h) {
				kept = append(kept, h)
			}
		}
		if len(kept) == 0 {
			kept = nil
		}
		svc.KnownVulns = kept
	}
	return Factors(svc.Vulns)
}

// hintFixedByDistro reports whether a passive eol hint the snapshot did not match is fixed in
// the service's distribution package according to the fix table.
func hintFixedByDistro(svc *domain.Service, h domain.VulnHint) bool {
	def := lookupDef(h.Product)
	if def == nil || !h.DistroPackaged {
		return false
	}
	c := candidate{def: def, version: h.Version, via: nonEmpty(svc.VersionSource, "nmap")}
	v, ctx := packageEvidence(svc, c)
	return fixedByDistro(def.Key, h.ID, ParseDistroPackage(def.Key, v, ctx))
}

// Factors converts the summaries into interestingness factors (one per kind, strongest
// product first). Matches on distribution packages are in VulnSummary.Backported and never
// reach the counts used here (a summary with only those has Total 0, DistroBackport set);
// incomplete-version matches count as "possible". The
// EPSS factor names a CVE other than the KEV ones: a KEV entry's high EPSS is the same
// evidence and is not counted twice.
func Factors(vulns []domain.VulnSummary) []domain.InterestingnessFactor {
	var kevIDs, kevPossible []string
	var maxEPSS, maxCVSS float64
	epssID, cvssLabel := "", ""
	type epssCand struct {
		id   string
		epss float64
	}
	var epssCands []epssCand
	for _, v := range vulns {
		definite := !v.DistroBackport && v.Confidence != "low"
		for _, c := range v.Top {
			if !c.KEV {
				continue
			}
			if definite && !c.Possible {
				kevIDs = append(kevIDs, c.ID)
			} else {
				kevPossible = append(kevPossible, c.ID)
			}
		}
		if v.KEV > 0 && len(kevIDs) == 0 && len(kevPossible) == 0 {
			kevPossible = append(kevPossible, v.Product)
		}
		if !definite {
			continue
		}
		for _, c := range v.Top {
			if !c.Possible {
				epssCands = append(epssCands, epssCand{c.ID, c.EPSS})
			}
		}
		if v.MaxCVSS > maxCVSS && v.Total > v.Possible {
			maxCVSS = v.MaxCVSS
			cvssLabel = fmt.Sprintf("%s %s: %d CVEs, max CVSS %.1f", v.Product, versionShort(v.Version), v.Total, v.MaxCVSS)
		}
	}
	isKEV := map[string]bool{}
	for _, id := range kevIDs {
		isKEV[id] = true
	}
	for _, c := range epssCands {
		if !isKEV[c.id] && c.epss > maxEPSS {
			maxEPSS, epssID = c.epss, c.id
		}
	}
	var out []domain.InterestingnessFactor
	switch {
	case len(kevIDs) > 0:
		out = append(out, domain.InterestingnessFactor{Reason: FactorKEV + strings.Join(kevIDs, ", "), Points: PointsKEV})
	case len(kevPossible) > 0:
		out = append(out, domain.InterestingnessFactor{Reason: FactorKEV + "possible, " + strings.Join(kevPossible, ", "), Points: PointsKEVPossible})
	}
	switch {
	case maxEPSS >= 0.5:
		out = append(out, domain.InterestingnessFactor{Reason: fmt.Sprintf("%s%s %.0f%%", FactorEPSS, epssID, maxEPSS*100), Points: PointsEPSSHigh})
	case maxEPSS >= 0.1:
		out = append(out, domain.InterestingnessFactor{Reason: fmt.Sprintf("%s%s %.0f%%", FactorEPSS, epssID, maxEPSS*100), Points: PointsEPSSMedium})
	}
	switch {
	case maxCVSS >= 9:
		out = append(out, domain.InterestingnessFactor{Reason: FactorCVSS + cvssLabel, Points: PointsCVSSCritical})
	case maxCVSS >= 7:
		out = append(out, domain.InterestingnessFactor{Reason: FactorCVSS + cvssLabel, Points: PointsCVSSHigh})
	}
	return out
}

func versionShort(v string) string {
	if i := strings.IndexByte(strings.TrimSpace(v), ' '); i > 0 {
		return strings.TrimSpace(v)[:i]
	}
	return strings.TrimSpace(v)
}

func dateOnly(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ts
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
