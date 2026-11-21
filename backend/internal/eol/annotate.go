package eol

import (
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Interestingness points for the derived flags.
const (
	PointsEOL       = 15
	PointsKnownVuln = 20
	TagEOL          = "eol"
	TagKnownVuln    = "known-vuln"
	factorPrefixEOL = "EOL version: "
	factorPrefixCVE = "Passive CVE hint: "
)

// derivedFactorPrefixes also lists the pre-translation (Polish) prefixes so factors stored
// by older versions are replaced rather than counted twice.
var derivedFactorPrefixes = []string{factorPrefixEOL, factorPrefixCVE, "Wersja EOL: ", "Pasywna wskazówka CVE: "}

func isDerivedFactor(reason string) bool {
	for _, p := range derivedFactorPrefixes {
		if strings.HasPrefix(reason, p) {
			return true
		}
	}
	return false
}

// Annotate fills svc.Outdated / svc.KnownVulns from the offline table (read-time view).
func Annotate(svc *domain.Service, now time.Time) {
	if svc == nil {
		return
	}
	svc.Outdated, svc.KnownVulns = Assess(svc, now)
}

// AnnotateHosts annotates every service of every host in place.
func AnnotateHosts(hosts []domain.Host, now time.Time) {
	for i := range hosts {
		AnnotateServices(hosts[i].Services, now)
	}
}

// AnnotateServices annotates services in place.
func AnnotateServices(services []domain.Service, now time.Time) {
	for i := range services {
		Annotate(&services[i], now)
	}
}

// ApplyScore annotates svc and folds the result into its interestingness factors, score
// (capped at 100) and tags ("eol", "known-vuln"). Used once on ingest; idempotent.
func ApplyScore(svc *domain.Service, now time.Time) {
	if svc == nil {
		return
	}
	Annotate(svc, now)
	kept := svc.InterestingFactors[:0:0]
	for _, f := range svc.InterestingFactors {
		if !isDerivedFactor(f.Reason) {
			kept = append(kept, f)
		}
	}
	if len(svc.Outdated) > 0 {
		labels := make([]string, 0, len(svc.Outdated))
		for _, o := range svc.Outdated {
			labels = append(labels, o.Label)
		}
		kept = append(kept, domain.InterestingnessFactor{Reason: factorPrefixEOL + strings.Join(labels, "; "), Points: PointsEOL})
		svc.Tags = addTag(svc.Tags, TagEOL)
	}
	if len(svc.KnownVulns) > 0 {
		ids := make([]string, 0, len(svc.KnownVulns))
		for _, h := range svc.KnownVulns {
			ids = append(ids, h.ID)
		}
		kept = append(kept, domain.InterestingnessFactor{Reason: factorPrefixCVE + strings.Join(ids, ", "), Points: PointsKnownVuln})
		svc.Tags = addTag(svc.Tags, TagKnownVuln)
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Points > kept[j].Points })
	total := 0
	for _, f := range kept {
		total += f.Points
	}
	if total > 100 {
		total = 100
	}
	svc.InterestingFactors = kept
	svc.Interestingness = total
}

func addTag(tags []string, t string) []string {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return tags
		}
	}
	return append(tags, t)
}
