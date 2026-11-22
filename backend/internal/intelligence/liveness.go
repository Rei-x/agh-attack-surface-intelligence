package intelligence

// Bayesian host liveness model: "after how many unanswered scans is a host gone?"
//
// Two quantities are kept apart:
//
//  1. Availability while alive, per time-of-day slot s (00-06, 06-12, 12-18, 18-24):
//     p_s ~ Beta(alpha_s, beta_s). A response adds 1 to alpha_s; a miss that is
//     later "explained" by the host coming back adds 1 to beta_s (it was downtime,
//     not death). Old evidence is exponentially forgotten with half-life H, so a
//     host whose behaviour changed is re-learned within ~2H.
//
//  2. The current outage: k_s consecutive misses per slot since the last response.
//     If the host still exists, the chance of seeing exactly these misses is the
//     beta-binomial term  L = prod_s prod_{i<k_s} (beta_s+i)/(alpha_s+beta_s+i);
//     if the host is gone, the misses are certain (likelihood 1). Bayes:
//
//     P(alive | outage) = pi*L / (pi*L + (1-pi))
//
// The host is reported INACTIVE when P(alive | outage) < threshold (default 5%)
// AND the operator's minimum guards hold (profile missing_threshold and
// grace_period_hours). Consequences:
//   - a rock-solid host (always answered) is INACTIVE after ~2-3 misses;
//   - a flapping host (answers 50%) needs ~10+ misses, because misses are normal for it;
//   - a lab PC that is always off at night never becomes INACTIVE from night misses
//     (beta_night is large, so L stays ~1); it becomes INACTIVE only when it also stops
//     answering in the day slots where it used to answer.

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const livenessModelName = "beta-bernoulli/4-slot/forgetting"

func normalizeLivenessConfig(cfg LifecycleConfig) LifecycleConfig {
	if cfg.InactiveProbability <= 0 || cfg.InactiveProbability >= 1 {
		cfg.InactiveProbability = 0.05
	}
	if cfg.PriorAlive <= 0 || cfg.PriorAlive >= 1 {
		cfg.PriorAlive = 0.9
	}
	if cfg.PriorUpAlpha <= 0 {
		cfg.PriorUpAlpha = 2
	}
	if cfg.PriorUpBeta <= 0 {
		cfg.PriorUpBeta = 0.5
	}
	if cfg.HalfLifeHours <= 0 {
		cfg.HalfLifeHours = 14 * 24
	}
	return cfg
}

// decayFactor returns 2^(-dt/H): evidence that is one half-life old weighs 0.5.
func decayFactor(from, to time.Time, halfLifeHours float64) float64 {
	if from.IsZero() || !to.After(from) {
		return 1
	}
	return math.Exp2(-to.Sub(from).Hours() / halfLifeHours)
}

// ensurePosterior lazily initialises the posterior of a slot. A host without a stored
// posterior is seeded from its Seen/Total counters.
func ensurePosterior(s *domain.TimeSlotStat, cfg LifecycleConfig) {
	if s.Alpha > 0 && s.Beta > 0 {
		return
	}
	s.Alpha = cfg.PriorUpAlpha + float64(s.Seen)
	misses := s.Total - s.Seen
	if misses < 0 {
		misses = 0
	}
	s.Beta = cfg.PriorUpBeta + float64(misses)
}

// decayedPosterior returns the slot posterior forgotten up to time `at`
// (only the evidence part decays; the prior is constant).
func decayedPosterior(s domain.TimeSlotStat, at time.Time, cfg LifecycleConfig) (alpha, beta float64) {
	ensurePosterior(&s, cfg)
	f := decayFactor(s.UpdatedAt, at, cfg.HalfLifeHours)
	alpha = cfg.PriorUpAlpha + math.Max(0, s.Alpha-cfg.PriorUpAlpha)*f
	beta = cfg.PriorUpBeta + math.Max(0, s.Beta-cfg.PriorUpBeta)*f
	return alpha, beta
}

// updateLivenessPosterior applies one observation to the slot posteriors.
// wasInactive: a return after an INACTIVE period is a resurrection, not downtime,
// so that outage is discarded instead of being folded into beta.
func updateLivenessPosterior(stats []domain.TimeSlotStat, slot string, alive bool, at time.Time, wasInactive bool, cfg LifecycleConfig) {
	for i := range stats {
		s := &stats[i]
		ensurePosterior(s, cfg)
		if alive && s.StreakMisses > 0 {
			if !wasInactive {
				a, b := decayedPosterior(*s, at, cfg)
				s.Alpha, s.Beta = a, b+float64(s.StreakMisses)
				s.UpdatedAt = at
			}
			s.StreakMisses = 0
		}
		if s.Slot != slot {
			s.PUp = roundRatio(s.Alpha / (s.Alpha + s.Beta))
			continue
		}
		a, b := decayedPosterior(*s, at, cfg)
		s.Alpha, s.Beta = a, b
		if alive {
			s.Alpha++
		} else {
			s.StreakMisses++
		}
		s.UpdatedAt = at
		s.PUp = roundRatio(s.Alpha / (s.Alpha + s.Beta))
	}
}

// EstimateLiveness computes P(host still exists) from the persisted slot
// posteriors and the current outage. It is pure and can be evaluated at read time.
func EstimateLiveness(host domain.Host, at time.Time, cfg LifecycleConfig) domain.LivenessEstimate {
	cfg = normalizeLivenessConfig(cfg)
	if at.IsZero() {
		at = time.Now().UTC()
	}
	slot := domain.TimeSlotFor(at)
	stats := EnsureTimeSlots(host.TimeOfDayStats)

	logL := 0.0
	total := 0
	var parts []string
	pUpSlot := 0.0
	for _, s := range stats {
		a, b := decayedPosterior(s, at, cfg)
		if s.Slot == slot {
			pUpSlot = a / (a + b)
		}
		k := s.StreakMisses
		if k <= 0 {
			continue
		}
		total += k
		for i := 0; i < k; i++ {
			logL += math.Log((b + float64(i)) / (a + b + float64(i)))
		}
		parts = append(parts, fmt.Sprintf("%s %s: %d× (hist. availability %d%%)", slotName(s.Slot), s.Slot, k, pct(a/(a+b))))
	}

	pi := cfg.PriorAlive
	L := math.Exp(logL)
	pAlive := pi * L / (pi*L + (1 - pi))
	if total == 0 {
		pAlive = 1
	}
	est := domain.LivenessEstimate{
		PAlive:       roundRatio(pAlive),
		PUpSlot:      roundRatio(pAlive * pUpSlot),
		Slot:         slot,
		StreakMisses: total,
		Threshold:    cfg.InactiveProbability,
		Model:        fmt.Sprintf("%s (H=%.0fh, prior Beta(%.1f,%.1f), P0(exists)=%.2f)", livenessModelName, cfg.HalfLifeHours, cfg.PriorUpAlpha, cfg.PriorUpBeta, cfg.PriorAlive),
	}
	if total == 0 {
		est.Reason = fmt.Sprintf("host responds; expected availability in the %s %s: %d%%", slotName(slot), slot, pct(pUpSlot))
	} else {
		est.Reason = fmt.Sprintf("probability the host is still up: %d%% after %d failed probes (%s)", pct(pAlive), total, strings.Join(parts, "; "))
	}
	return est
}

func slotName(slot string) string {
	switch slot {
	case domain.SlotNight:
		return "night window"
	case domain.SlotMorning:
		return "morning window"
	case domain.SlotAfternoon:
		return "afternoon window"
	case domain.SlotEvening:
		return "evening window"
	}
	return "window"
}

func pct(p float64) int {
	return int(math.Round(p * 100))
}
