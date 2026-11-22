package eol

import (
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Standalone weights of the derived flags (domain.CombineFactors). An end-of-life branch or a
// passive, version-only CVE hint is worth a look, not an alarm: on its own it stays in the
// low band.
const (
	PointsEOL       = 12
	PointsKnownVuln = 15
	TagEOL          = "eol"
	TagKnownVuln    = "known-vuln"
	factorPrefixEOL = "EOL version: "
	factorPrefixCVE = "Passive CVE hint: "
)

// derivedFactorPrefixes also lists the pre-translation (Polish) prefixes so factors stored
// by older versions are replaced rather than counted twice.
var derivedFactorPrefixes = []string{factorPrefixEOL, factorPrefixCVE, "Wersja EOL: ", "Pasywna wskazówka CVE: "}

// Annotator derives extra read-time fields of a service (internal/vulndb, internal/verify)
// and returns the interestingness factors they contribute (used by ApplyScore only).
type Annotator func(svc *domain.Service, now time.Time) []domain.InterestingnessFactor

var annotators []Annotator

// RegisterAnnotator adds an annotator run by every Annotate / ApplyScore call. Factors it
// returns must start with one of factorPrefixes so a re-score replaces them instead of
// counting them twice. Call during startup (not concurrently with Annotate).
func RegisterAnnotator(fn Annotator, factorPrefixes ...string) {
	annotators = append(annotators, fn)
	derivedFactorPrefixes = append(derivedFactorPrefixes, factorPrefixes...)
}

func runAnnotators(svc *domain.Service, now time.Time) []domain.InterestingnessFactor {
	var out []domain.InterestingnessFactor
	for _, fn := range annotators {
		out = append(out, fn(svc, now)...)
	}
	return out
}

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
	runAnnotators(svc, now)
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

// ApplyScore annotates svc and folds the result into its interestingness factors and score
// (domain.CombineFactors: diminishing returns, Points add up to the score) and its tags
// ("eol", "known-vuln"). Used once on ingest; idempotent.
func ApplyScore(svc *domain.Service, now time.Time) {
	if svc == nil {
		return
	}
	svc.Outdated, svc.KnownVulns = Assess(svc, now)
	extra := runAnnotators(svc, now)
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
	kept = append(kept, extra...)
	svc.Interestingness, svc.InterestingFactors = domain.CombineFactors(kept)
}

func addTag(tags []string, t string) []string {
	for _, x := range tags {
		if strings.EqualFold(x, t) {
			return tags
		}
	}
	return append(tags, t)
}
