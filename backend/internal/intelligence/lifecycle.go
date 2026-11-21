package intelligence

import (
	"fmt"
	"math"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// LifecycleConfig controls host hysteresis thresholds and grace periods.
type LifecycleConfig struct {
	MissingThreshold int // consecutive missed scans required before INACTIVE (default 3)
	GracePeriodHours int // minimum hours since LastSeen before INACTIVE (default 72)
}

// DefaultLifecycleConfig returns conservative production defaults for CBI AGH.
func DefaultLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		MissingThreshold: 3,
		GracePeriodHours: 72,
	}
}

func normalizeLifecycleConfig(cfg LifecycleConfig) LifecycleConfig {
	if cfg.MissingThreshold <= 0 {
		cfg.MissingThreshold = 3
	}
	if cfg.GracePeriodHours <= 0 {
		cfg.GracePeriodHours = 72
	}
	return cfg
}

// TransitionResult summarizes a host lifecycle evaluation step and time-of-day analysis.
type TransitionResult struct {
	PreviousState      string `json:"previous_state"`
	NewState           string `json:"new_state"`
	Transitioned       bool   `json:"transitioned"`
	StabilityScore     int    `json:"stability_score"`
	Reason             string `json:"reason"`
	TimeSlot           string `json:"time_slot"`
	IsExpectedSchedule bool   `json:"is_expected_schedule"`
	IsTimeAnomaly      bool   `json:"is_time_anomaly"`
}

var allTimeSlots = []string{
	domain.SlotNight,
	domain.SlotMorning,
	domain.SlotAfternoon,
	domain.SlotEvening,
}

// EnsureTimeSlots guarantees all 4 daily time slots exist in deterministic order.
func EnsureTimeSlots(stats []domain.TimeSlotStat) []domain.TimeSlotStat {
	bySlot := make(map[string]domain.TimeSlotStat, len(stats))
	for _, s := range stats {
		bySlot[s.Slot] = s
	}
	out := make([]domain.TimeSlotStat, 0, 4)
	for _, slot := range allTimeSlots {
		if s, ok := bySlot[slot]; ok {
			if s.Total > 0 {
				s.Ratio = roundRatio(float64(s.Seen) / float64(s.Total))
			}
			out = append(out, s)
		} else {
			out = append(out, domain.TimeSlotStat{Slot: slot})
		}
	}
	return out
}

// ClassifyTimeAvailability compares the current observation against historical
// time-of-day slot ratios to distinguish expected off-hours schedules from anomalies.
func ClassifyTimeAvailability(stats []domain.TimeSlotStat, slot string, observedAlive bool) (isExpectedSchedule bool, isTimeAnomaly bool) {
	ensured := EnsureTimeSlots(stats)
	var current domain.TimeSlotStat
	var maxOtherRatio float64
	var otherWithData int

	for _, s := range ensured {
		if s.Slot == slot {
			current = s
		} else if s.Total >= 2 {
			otherWithData++
			if s.Ratio > maxOtherRatio {
				maxOtherRatio = s.Ratio
			}
		}
	}

	// Need at least 3 baseline observations in the current slot to classify confidently.
	if current.Total < 3 {
		return false, false
	}

	if !observedAlive {
		// Host is OFF right now.
		if current.Ratio <= 0.25 && otherWithData > 0 && maxOtherRatio >= 0.70 {
			// Historically off during this time slot (e.g. night lab shutdown) and active in other slots.
			return true, false
		}
		if current.Ratio >= 0.80 {
			// Host is almost always UP in this slot, yet disappeared unexpectedly.
			return false, true
		}
		return false, false
	}

	// Host is ON right now.
	if current.Ratio <= 0.20 && otherWithData > 0 && maxOtherRatio >= 0.70 {
		// Host is normally shut down in this slot, yet suddenly appeared -> TIME_ANOMALY!
		return false, true
	}
	return false, false
}

// EvaluateHostLifecycle advances the host hysteresis state machine, updates stability
// metrics and the 4-slot Time-of-Day Availability Matrix, and classifies schedule anomalies.
func EvaluateHostLifecycle(host *domain.Host, observedAlive bool, observedAt time.Time, cfg LifecycleConfig) TransitionResult {
	cfg = normalizeLifecycleConfig(cfg)
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	slot := domain.TimeSlotFor(observedAt)
	host.TimeOfDayStats = EnsureTimeSlots(host.TimeOfDayStats)

	// Classify against historical baseline BEFORE adding the current observation.
	isExpected, isAnomaly := ClassifyTimeAvailability(host.TimeOfDayStats, slot, observedAlive)

	prevState := host.LifecycleState
	var newState string
	var reason string

	host.TotalScansChecked++

	if observedAlive {
		if host.FirstSeen.IsZero() {
			host.FirstSeen = observedAt
		}
		host.LastSeen = observedAt
		host.TotalScansSeen++
		host.ConsecutiveMisses = 0

		switch prevState {
		case "":
			newState = domain.HostStateNew
			reason = "first time host observed online"
		case domain.HostStateNew:
			newState = domain.HostStateActive
			reason = "host confirmed online on subsequent scan"
		case domain.HostStateInactive:
			newState = domain.HostStateReactivated
			host.StateTransitions++
			reason = "previously inactive host returned online"
		case domain.HostStateReactivated:
			newState = domain.HostStateActive
			reason = "reactivated host remained online"
		case domain.HostStateMissing:
			host.StateTransitions++
			// Repeated up/down flapping classifies host as INTERMITTENT.
			if host.StateTransitions >= 2 {
				newState = domain.HostStateIntermittent
				reason = fmt.Sprintf("host recovered from MISSING with %d state transitions (flapping)", host.StateTransitions)
			} else {
				newState = domain.HostStateActive
				reason = "host recovered from temporary MISSING state"
			}
		case domain.HostStateIntermittent:
			seenRatio := float64(host.TotalScansSeen) / float64(host.TotalScansChecked)
			if host.TotalScansChecked >= 6 && seenRatio >= 0.85 {
				newState = domain.HostStateActive
				reason = "intermittent host stabilized"
			} else {
				newState = domain.HostStateIntermittent
				reason = "intermittent host observed online"
			}
		default:
			newState = domain.HostStateActive
			reason = "host remains active"
		}
	} else {
		host.ConsecutiveMisses++
		graceDuration := time.Duration(cfg.GracePeriodHours) * time.Hour
		elapsedSinceLastSeen := time.Duration(0)
		if !host.LastSeen.IsZero() {
			elapsedSinceLastSeen = observedAt.Sub(host.LastSeen)
		}

		meetsMisses := host.ConsecutiveMisses >= cfg.MissingThreshold
		meetsGrace := host.LastSeen.IsZero() || elapsedSinceLastSeen >= graceDuration

		switch {
		case prevState == "":
			newState = domain.HostStateInactive
			reason = "host never observed online"
		case prevState == domain.HostStateInactive:
			newState = domain.HostStateInactive
			reason = "host remains inactive"
		case meetsMisses && meetsGrace:
			newState = domain.HostStateInactive
			if prevState != domain.HostStateInactive {
				host.StateTransitions++
			}
			reason = fmt.Sprintf("missed %d consecutive scans (>= %d) and exceeded %dh grace period", host.ConsecutiveMisses, cfg.MissingThreshold, cfg.GracePeriodHours)
		default:
			newState = domain.HostStateMissing
			if prevState != domain.HostStateMissing {
				host.StateTransitions++
			}
			if isExpected {
				reason = fmt.Sprintf("host offline during expected off-hours slot %s (%d/%d misses)", slot, host.ConsecutiveMisses, cfg.MissingThreshold)
			} else {
				reason = fmt.Sprintf("host missed scan (%d/%d misses, grace period not yet elapsed)", host.ConsecutiveMisses, cfg.MissingThreshold)
			}
		}
	}

	// Update Time-of-Day Availability Matrix slot counters.
	for i := range host.TimeOfDayStats {
		if host.TimeOfDayStats[i].Slot == slot {
			host.TimeOfDayStats[i].Total++
			if observedAlive {
				host.TimeOfDayStats[i].Seen++
			}
			host.TimeOfDayStats[i].Ratio = roundRatio(float64(host.TimeOfDayStats[i].Seen) / float64(host.TimeOfDayStats[i].Total))
			break
		}
	}

	host.LifecycleState = newState
	host.StabilityScore = computeStabilityScore(host.TotalScansSeen, host.TotalScansChecked, host.StateTransitions)

	return TransitionResult{
		PreviousState:      prevState,
		NewState:           newState,
		Transitioned:       prevState != "" && prevState != newState,
		StabilityScore:     host.StabilityScore,
		Reason:             reason,
		TimeSlot:           slot,
		IsExpectedSchedule: isExpected,
		IsTimeAnomaly:      isAnomaly,
	}
}

func computeStabilityScore(seen, checked, transitions int) int {
	if checked <= 0 {
		return 100
	}
	seenRatio := float64(seen) / float64(checked)
	// Penalize frequent transitions relative to total checks.
	flapRate := float64(transitions) / float64(checked)
	score := (seenRatio * 100.0) - (flapRate * 45.0)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return int(math.Round(score))
}

func roundRatio(r float64) float64 {
	return math.Round(r*1000) / 1000
}
