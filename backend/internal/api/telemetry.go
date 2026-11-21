package api

import (
	"context"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Run telemetry: the governor's backoffs, timeouts/429/RST counts, configured vs effective
// rates and window pauses are live events; they are also folded into a per-run document in
// the settings store so the scan list can show them after the fact (local and agent runs:
// agents relay the same events).

const maxThrottleEntries = 50

var runTelemetryMu sync.Mutex

func runTelemetryKey(runID string) string { return "run_telemetry:" + runID }

// loadRunTelemetry returns the stored telemetry of a run, nil when none was recorded.
func loadRunTelemetry(ctx context.Context, store db.Store, runID string) *domain.ScanTelemetry {
	ss, ok := store.(db.SettingsStore)
	if !ok || runID == "" {
		return nil
	}
	var t domain.ScanTelemetry
	if found, err := ss.GetSetting(ctx, runTelemetryKey(runID), &t); err != nil || !found {
		return nil
	}
	return &t
}

func floatOf(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

func (s *Server) observeRunTelemetry(ev domain.LiveEvent) {
	switch ev.Type {
	case "governor.throttle", "scan.budget", "scan.paused_window", "scan.window_resumed":
	default:
		return
	}
	if ev.ScanRunID == "" {
		return
	}
	ss, ok := s.store.(db.SettingsStore)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runTelemetryMu.Lock()
	defer runTelemetryMu.Unlock()
	t := loadRunTelemetry(ctx, s.store, ev.ScanRunID)
	if t == nil {
		t = &domain.ScanTelemetry{}
		if run, err := s.store.GetScanRun(ctx, ev.ScanRunID); err == nil && run.ProfileID != "" {
			if p, err := s.store.GetProfile(ctx, run.ProfileID); err == nil && p != nil {
				t.ConfiguredPPS, t.ConfiguredHTTPRPS = p.MaxRatePPS, p.HTTPRPS
			}
		}
	}
	p := ev.Payload
	at := ev.Timestamp
	if at.IsZero() {
		at = time.Now().UTC()
	}
	switch ev.Type {
	case "governor.throttle":
		host, _ := p["host"].(string)
		reason, _ := p["reason"].(string)
		t.Throttles = append(t.Throttles, domain.ThrottleEntry{At: at, Host: host, Reason: reason,
			OldRate: floatOf(p["old_rate"]), NewRate: floatOf(p["new_rate"]), Errors: int(floatOf(p["error_count"]))})
		if len(t.Throttles) > maxThrottleEntries {
			t.Throttles = t.Throttles[len(t.Throttles)-maxThrottleEntries:]
		}
		t.ThrottleCount++
	case "scan.budget":
		// One per window segment: counters are per segment, so they add up.
		if v := int(floatOf(p["max_rate_pps"])); v > 0 && t.ConfiguredPPS == 0 {
			t.ConfiguredPPS = v
		}
		if v := int(floatOf(p["nmap_peak_granted_pps"])); v > t.NmapPeakPPS {
			t.NmapPeakPPS = v
		}
		if v := floatOf(p["governor_rate"]); v > 0 {
			t.HTTPRateRPS = v
		}
		if v := floatOf(p["governor_initial_rate"]); v > 0 {
			t.HTTPInitialRPS = v
		}
		t.Timeouts += int(floatOf(p["timeouts"]))
		t.HTTP429 += int(floatOf(p["http_429"]))
		t.RST += int(floatOf(p["rst"]))
	case "scan.paused_window":
		next, _ := p["next_window_open"].(string)
		t.WindowEvents = append(t.WindowEvents, domain.WindowEntry{At: at, Kind: "paused", NextOpen: next})
	case "scan.window_resumed":
		t.WindowEvents = append(t.WindowEvents, domain.WindowEntry{At: at, Kind: "resumed"})
	}
	t.UpdatedAt = time.Now().UTC()
	_ = ss.SaveSetting(ctx, runTelemetryKey(ev.ScanRunID), t)
}
