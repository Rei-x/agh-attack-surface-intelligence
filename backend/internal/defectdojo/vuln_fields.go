package defectdojo

import (
	"fmt"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Known-vulnerability (internal/vulndb) and verified (internal/verify) evidence on the
// change findings. They are ordinary findings of the same "Dzięcioł changes" test, so the
// DefectDojo lifecycle (dedup, close_old_findings, triage sync) applies unchanged; what is
// added is the evidence DefectDojo can prioritise on: CVE ids, CVSS, EPSS and KEV.

const maxVulnIDs = 60 // vulnerability_ids sent per finding (top first)

// vulnTitle: stable facts only (product, version, where); counts live in the description.
func vulnTitle(v domain.VulnSummary, where string) string {
	prefix := "Known vulnerabilities"
	if v.KEV > 0 {
		prefix = "Known exploited vulnerability (CISA KEV)"
	}
	return fmt.Sprintf("%s: %s %s on %s", prefix, v.Product, versionShort(v.Version), where)
}

// vulnSeverity: KEV or CVSS >= 9 is Critical, >= 7 High, >= 4 Medium, else Low; a match that
// is only possible (distro backport, incomplete version) drops one level.
func vulnSeverity(v domain.VulnSummary) string {
	levels := []string{"Info", "Low", "Medium", "High", "Critical"}
	i := 1
	switch {
	case v.KEV > 0 || v.MaxCVSS >= 9:
		i = 4
	case v.MaxCVSS >= 7:
		i = 3
	case v.MaxCVSS >= 4:
		i = 2
	}
	if v.Confidence == "low" || v.Total == v.Possible {
		i--
	}
	return levels[i]
}

func vulnEvidence(v domain.VulnSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s matches %d CVEs in the offline NVD snapshot (%d critical, %d high, %d medium, %d low; max CVSS %.1f).",
		v.Product, versionShort(v.Version), v.Total, v.Critical, v.High, v.Medium, v.Low, v.MaxCVSS)
	if v.KEV > 0 {
		fmt.Fprintf(&b, " %d of them are in CISA KEV (exploited in the wild)", v.KEV)
		if v.Ransomware {
			b.WriteString(", including use in ransomware campaigns")
		}
		b.WriteString(".")
	}
	fmt.Fprintf(&b, " Highest EPSS: %.1f%% (percentile %.1f).", v.MaxEPSS*100, v.MaxEPSSPercentile*100)
	fmt.Fprintf(&b, "\n\n**Version match confidence:** %s. %s", v.Confidence, v.ConfidenceNote)
	b.WriteString("\n\n**Top CVEs:**\n")
	for _, c := range v.Top {
		kev := ""
		if c.KEV {
			kev = " **KEV**"
		}
		possible := ""
		if c.Possible {
			possible = " (possible)"
		}
		fmt.Fprintf(&b, "- [%s](%s) CVSS %.1f, EPSS %.1f%%%s%s: %s\n", c.ID, c.URL, c.CVSS, c.EPSS*100, kev, possible, c.Summary)
	}
	fmt.Fprintf(&b, "\nSource: NVD CVE API 2.0, CISA KEV, FIRST EPSS (snapshot of %s, version-only match, nothing was sent to the service).", v.DataAsOf)
	return b.String()
}

func applyVulnFields(g *genericFinding, v domain.VulnSummary) {
	g.ComponentName, g.ComponentVersion = v.Product, versionShort(v.Version)
	ids := v.CVEIDs
	if len(ids) > maxVulnIDs {
		ids = ids[:maxVulnIDs]
	}
	if len(ids) > 0 {
		g.CVE = ids[0]
		if len(ids) > 1 {
			g.VulnerabilityIDs = append([]string(nil), ids[1:]...)
		}
	}
	g.CVSSv3Score = v.MaxCVSS
	g.EPSSScore, g.EPSSPercentile = v.MaxEPSS, v.MaxEPSSPercentile
	if v.KEV > 0 {
		g.KnownExploited, g.RansomwareUsed = true, v.Ransomware
		for _, c := range v.Top {
			if c.KEV && c.KEVDateAdded != "" && (g.KEVDate == "" || c.KEVDateAdded < g.KEVDate) {
				g.KEVDate = c.KEVDateAdded
			}
		}
	}
	var refs []string
	for _, c := range v.Top {
		refs = append(refs, c.URL)
	}
	g.References = strings.Join(refs, "\n")
	g.SeverityJustification = fmt.Sprintf("KEV: %d, max EPSS %.3f, max CVSS %.1f, version match confidence %s.", v.KEV, v.MaxEPSS, v.MaxCVSS, v.Confidence)
	g.Mitigation = fmt.Sprintf("Upgrade %s to a fixed release (see the CVE references).", v.Product)
	if v.DistroBackport {
		g.Mitigation += " This is a distribution build: check the package changelog, the fix may already be backported."
	}
	g.Tags = append(g.Tags, "cve")
	if v.KEV > 0 {
		g.Tags = append(g.Tags, "kev")
	}
}

func verifiedSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return "Info"
}

// verifiedEvidence is stable across runs (no timestamps, no response bytes): the response
// snippet changes (uptime counters, dates) and goes to steps_to_reproduce instead.
func verifiedEvidence(f domain.VerifiedFinding) string {
	return fmt.Sprintf("Confirmed by the safe verification check `%s` (read-only request, no exploitation). %s", f.CheckID, firstLine(f.Request))
}

func applyVerifiedFields(g *genericFinding, f domain.VerifiedFinding) {
	g.Verified = true
	g.VulnIDFromTool = f.CheckID
	g.Mitigation = f.Remediation
	g.References = strings.Join(f.References, "\n")
	g.StepsToReproduce = fmt.Sprintf("Request:\n```\n%s\n```\nResponse (secrets redacted):\n```\n%s\n```\nChecked at %s.", f.Request, f.Evidence, f.CheckedAt.UTC().Format("2006-01-02 15:04 UTC"))
	g.Tags = append(g.Tags, "verified", "check:"+f.CheckID)
	if f.DefaultCreds {
		g.Tags = append(g.Tags, "default-credentials")
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return "Request: `" + s[:i] + "`."
	}
	if s == "" {
		return ""
	}
	return "Request: `" + s + "`."
}
