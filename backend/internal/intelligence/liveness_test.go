package intelligence

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Scans every 6h, one per time-of-day slot: 01:00, 07:00, 13:00, 19:00 UTC.
var livenessT0 = time.Date(2026, 3, 2, 1, 0, 0, 0, time.UTC)

func scanAt(i int) time.Time { return livenessT0.Add(time.Duration(i) * 6 * time.Hour) }

// Isolate the Bayesian rule: guards set to their weakest values.
var bayesOnly = LifecycleConfig{MissingThreshold: 1, GracePeriodHours: 1}

// replay feeds a history and returns the index of the first scan at which the
// host became INACTIVE (-1 if never) plus the last result.
func replay(host *domain.Host, up func(i int) bool, from, to int, cfg LifecycleConfig) (int, TransitionResult) {
	first := -1
	var last TransitionResult
	for i := from; i < to; i++ {
		last = EvaluateHostLifecycle(host, up(i), scanAt(i), cfg)
		if first < 0 && last.NewState == domain.HostStateInactive {
			first = i
		}
	}
	return first, last
}

func missesUntilInactive(t *testing.T, host *domain.Host, start int, cfg LifecycleConfig) (int, TransitionResult) {
	t.Helper()
	for k := 1; k <= 60; k++ {
		r := EvaluateHostLifecycle(host, false, scanAt(start+k-1), cfg)
		if r.NewState == domain.HostStateInactive {
			return k, r
		}
	}
	t.Fatalf("host never became INACTIVE after 60 misses")
	return 0, TransitionResult{}
}

func TestLivenessStableHostGoneQuickly(t *testing.T) {
	h := &domain.Host{IP: "10.0.0.1"}
	if first, _ := replay(h, func(int) bool { return true }, 0, 56, bayesOnly); first >= 0 {
		t.Fatalf("always-up host must never be INACTIVE, was at scan %d", first)
	}
	k, r := missesUntilInactive(t, h, 56, bayesOnly)
	if k > 3 {
		t.Fatalf("stable host should be declared gone after <=3 misses, took %d", k)
	}
	if r.Liveness.PAlive >= 0.05 || !strings.Contains(r.Reason, "prawdopodobieństwo") {
		t.Fatalf("expected posterior < 5%% with explanation, got %.3f %q", r.Liveness.PAlive, r.Reason)
	}
	t.Logf("stable: INACTIVE after %d misses; %s", k, r.Reason)
}

func TestLivenessFlappingHostNeedsMoreEvidence(t *testing.T) {
	// ~50% availability, deterministic pseudo-random pattern with runs of up to 3 misses.
	pattern := []bool{true, false, true, true, false, false, true, false, false, false, true, true, false, true}
	h := &domain.Host{IP: "10.0.0.2"}
	first, _ := replay(h, func(i int) bool { return i == 0 || pattern[i%len(pattern)] }, 0, 56, bayesOnly)
	if first >= 0 {
		t.Fatalf("flapping host must not be declared INACTIVE during normal flapping (scan %d)", first)
	}
	if h.LifecycleState != domain.HostStateIntermittent && h.LifecycleState != domain.HostStateMissing {
		t.Fatalf("flapping host should be INTERMITTENT/MISSING, got %s", h.LifecycleState)
	}
	// End on a seen scan so the outage starts fresh.
	EvaluateHostLifecycle(h, true, scanAt(56), bayesOnly)

	stable := &domain.Host{IP: "10.0.0.3"}
	replay(stable, func(int) bool { return true }, 0, 57, bayesOnly)
	kStable, _ := missesUntilInactive(t, stable, 57, bayesOnly)
	kFlap, r := missesUntilInactive(t, h, 57, bayesOnly)
	if kFlap < 2*kStable || kFlap < 6 {
		t.Fatalf("flapping host should need far more misses than a stable one: flap=%d stable=%d", kFlap, kStable)
	}
	t.Logf("flapping: INACTIVE after %d misses (stable: %d); %s", kFlap, kStable, r.Reason)
}

func TestLivenessTimeOfDayHostNotInactiveAtNight(t *testing.T) {
	// Lab PC: answers 07:00 and 13:00, always off at 01:00 and 19:00.
	daytime := func(i int) bool {
		s := domain.TimeSlotFor(scanAt(i))
		return s == domain.SlotMorning || s == domain.SlotAfternoon
	}
	h := &domain.Host{IP: "10.0.0.4"}
	// Start at a morning scan so the first sighting is online.
	first, _ := replay(h, daytime, 1, 59, DefaultLifecycleConfig()) // ends with 13:00 (seen)
	if first >= 0 {
		t.Fatalf("day-only host must never be INACTIVE because of night misses (scan %d)", first)
	}
	// Night/evening posterior must have learned "off", day "on".
	for _, s := range h.TimeOfDayStats {
		switch s.Slot {
		case domain.SlotNight, domain.SlotEvening:
			if s.PUp > 0.25 {
				t.Fatalf("slot %s availability should be learned low, got %.2f", s.Slot, s.PUp)
			}
		default:
			if s.PUp < 0.75 {
				t.Fatalf("slot %s availability should be high, got %.2f", s.Slot, s.PUp)
			}
		}
	}
	// A night miss is expected: P(alive) stays high.
	r := EvaluateHostLifecycle(h, false, scanAt(59), DefaultLifecycleConfig()) // 19:00
	r = EvaluateHostLifecycle(h, false, scanAt(60), DefaultLifecycleConfig())  // 01:00
	if r.Liveness.PAlive < 0.8 || r.NewState == domain.HostStateInactive {
		t.Fatalf("night outage of a day-only host should keep P(alive) high, got %.3f (%s)", r.Liveness.PAlive, r.NewState)
	}
	if !r.IsExpectedSchedule {
		t.Fatalf("night miss should be classified as expected schedule: %s", r.Reason)
	}

	// Truly gone: it now also misses the day slots -> INACTIVE once the day evidence is in.
	k, rGone := missesUntilInactive(t, h, 61, bayesOnly) // from 07:00 on
	dayMisses := 0
	for _, s := range h.TimeOfDayStats {
		if s.Slot == domain.SlotMorning || s.Slot == domain.SlotAfternoon {
			dayMisses += s.StreakMisses
		}
	}
	if dayMisses == 0 || dayMisses > 3 {
		t.Fatalf("expected INACTIVE after 1-3 day-slot misses, got %d day misses (k=%d)", dayMisses, k)
	}
	t.Logf("time-of-day: INACTIVE after %d further misses (%d in day slots); %s", k, dayMisses, rGone.Reason)
}

func TestLivenessGuardsStillApply(t *testing.T) {
	cfg := LifecycleConfig{MissingThreshold: 3, GracePeriodHours: 72}
	h := &domain.Host{IP: "10.0.0.5"}
	replay(h, func(int) bool { return true }, 0, 56, cfg)
	lastSeen := h.LastSeen
	for i := 56; i < 80; i++ {
		r := EvaluateHostLifecycle(h, false, scanAt(i), cfg)
		elapsed := scanAt(i).Sub(lastSeen)
		if r.NewState == domain.HostStateInactive {
			if elapsed < 72*time.Hour || h.ConsecutiveMisses < 3 {
				t.Fatalf("INACTIVE before minimum guards: %v elapsed, %d misses", elapsed, h.ConsecutiveMisses)
			}
			if !strings.Contains(r.Reason, "próg 5%") {
				t.Fatalf("reason should cite the threshold: %q", r.Reason)
			}
			return
		}
		if elapsed >= 72*time.Hour {
			t.Fatalf("stable host should be INACTIVE right after the 72h grace period, still %s (%s)", r.NewState, r.Reason)
		}
	}
	t.Fatal("never became INACTIVE")
}

func TestLivenessReturnAfterOutageCountsAsDowntime(t *testing.T) {
	h := &domain.Host{IP: "10.0.0.6"}
	replay(h, func(int) bool { return true }, 0, 20, bayesOnly)
	before := 0.0
	for _, s := range h.TimeOfDayStats {
		before += s.Beta
	}
	EvaluateHostLifecycle(h, false, scanAt(20), bayesOnly)
	EvaluateHostLifecycle(h, true, scanAt(21), bayesOnly) // came back: the miss was downtime
	after := 0.0
	streak := 0
	for _, s := range h.TimeOfDayStats {
		after += s.Beta
		streak += s.StreakMisses
	}
	if streak != 0 || after-before < 0.9 {
		t.Fatalf("explained miss must be folded into beta (before %.2f after %.2f, streak %d)", before, after, streak)
	}
	if h.Liveness == nil || h.Liveness.PAlive != 1 {
		t.Fatalf("host answering now must have p_alive=1, got %+v", h.Liveness)
	}
}

func TestLivenessForgettingHalfLife(t *testing.T) {
	if f := decayFactor(livenessT0, livenessT0.Add(336*time.Hour), 336); math.Abs(f-0.5) > 1e-9 {
		t.Fatalf("decay after one half-life = %v, want 0.5", f)
	}
	// Legacy host (pre-Bayes) is seeded from Seen/Total counters.
	h := domain.Host{TimeOfDayStats: []domain.TimeSlotStat{{Slot: domain.SlotMorning, Seen: 8, Total: 10}}}
	a, b := decayedPosterior(h.TimeOfDayStats[0], livenessT0, normalizeLivenessConfig(LifecycleConfig{}))
	if a != 10 || b != 2.5 {
		t.Fatalf("legacy seed alpha=%v beta=%v, want 10, 2.5", a, b)
	}
}
