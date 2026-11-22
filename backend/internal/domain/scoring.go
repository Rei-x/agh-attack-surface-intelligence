package domain

import (
	"math"
	"sort"
)

// Interestingness scoring with diminishing returns.
//
// Every factor has a Weight: the score it would justify on its own (an exploited-in-the-wild
// CVE 60, telnet 50, an admin panel 35, a missing header 2). Factors combine like
// independent probabilities, score = 100 * (1 - prod(1 - w/100)), strongest first, so each
// further factor only fills part of the remaining headroom: KEV 60 + admin panel 35 = 74,
// not 95. Points is what a factor actually added after that, so the Points of a factor list
// always add up to its score and the "why" list stays exact.
//
// Low-signal hygiene factors (missing security headers, cookie flags, self-signed or
// expiring certificates, auth prompts) are capped together at HygieneCap: on their own they
// keep a service in the lowest band, next to strong factors they add next to nothing.

// FactorKindHygiene marks a low-signal factor counted against HygieneCap.
const FactorKindHygiene = "hygiene"

// HygieneCap is the most all hygiene factors of one item add together.
const HygieneCap = 12

// CombineFactors computes the 0-100 score of factors and returns them ordered by
// contribution with Points set. It is idempotent: Weight is kept (legacy factors without a
// Weight use their Points as the weight), so a re-score gives the same result.
func CombineFactors(factors []InterestingnessFactor) (int, []InterestingnessFactor) {
	out := make([]InterestingnessFactor, 0, len(factors))
	for _, f := range factors {
		if f.Weight <= 0 {
			f.Weight = f.Points
		}
		if f.Weight <= 0 {
			continue
		}
		if f.Weight > 100 {
			f.Weight = 100
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Weight != out[j].Weight {
			return out[i].Weight > out[j].Weight
		}
		if (out[i].Kind == FactorKindHygiene) != (out[j].Kind == FactorKindHygiene) {
			return out[j].Kind == FactorKindHygiene
		}
		return out[i].Reason < out[j].Reason
	})
	score, hygiene := 0.0, 0.0
	shown := 0
	for i := range out {
		gain := (100 - score) * float64(out[i].Weight) / 100
		if out[i].Kind == FactorKindHygiene {
			gain = math.Max(0, math.Min(gain, HygieneCap-hygiene))
			hygiene += gain
		}
		score += gain
		// Cumulative rounding: the integer points add up to the rounded total exactly.
		next := int(math.Round(score))
		out[i].Points = next - shown
		shown = next
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Points > out[j].Points })
	if shown > 100 {
		shown = 100
	}
	return shown, out
}

// ScoreSeverity maps a service score to a DefectDojo severity: Critical >= 90, High >= 70,
// Medium >= 45, Low >= 20, else Info. With diminishing returns 90+ takes a confirmed
// (verified) or exploited-in-the-wild finding on top of a strong exposure, 70+ an applicable
// KEV CVE or unauthenticated control (Docker API, VNC without auth), 45+ cleartext remote
// administration or a management console with known CVEs; hygiene alone stays Info.
func ScoreSeverity(score int) string {
	switch {
	case score >= 90:
		return "Critical"
	case score >= 70:
		return "High"
	case score >= 45:
		return "Medium"
	case score >= 20:
		return "Low"
	}
	return "Info"
}
