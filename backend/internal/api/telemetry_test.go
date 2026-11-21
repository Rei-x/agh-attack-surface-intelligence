package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Governor backoffs, counters and window pauses published as live events end up on the run.
func TestRunTelemetryPersistedFromLiveEvents(t *testing.T) {
	srv, store, h := setupTestServer(t)
	ctx := context.Background()
	p := &domain.ScanProfile{Name: "night", Targets: []string{"10.0.0.0/24"}, MaxRatePPS: 800, HTTPRPS: 20}
	if err := store.CreateProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	run := &domain.ScanRun{ID: db.NewID(), ProfileID: p.ID, Name: "r", Status: domain.ScanStatusRunning, StartedAt: time.Now()}
	if err := store.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	pub := func(typ string, payload map[string]any) {
		srv.hub.Publish(domain.LiveEvent{Type: typ, ScanRunID: run.ID, Payload: payload})
	}
	pub("governor.throttle", map[string]any{"host": "10.0.0.5", "reason": "http_429", "old_rate": 80.0, "new_rate": 40.0, "error_count": 6})
	pub("scan.paused_window", map[string]any{"next_window_open": "2026-11-22T22:00:00+01:00"})
	pub("scan.window_resumed", map[string]any{})
	pub("scan.budget", map[string]any{"max_rate_pps": 800, "nmap_peak_granted_pps": 720, "governor_rate": 40.0, "governor_initial_rate": 80.0, "timeouts": 12, "http_429": 6, "rst": 0})

	tok := loginTest(t, h, "viewer", "Viewer123!")
	r := doJSON(h, http.MethodGet, "/api/v1/scans/"+run.ID, tok, nil)
	var got domain.ScanRun
	if err := json.Unmarshal(r.Body.Bytes(), &got); err != nil || got.Telemetry == nil {
		t.Fatalf("no telemetry: %d %s", r.Code, r.Body.String())
	}
	tm := got.Telemetry
	if tm.ConfiguredPPS != 800 || tm.ConfiguredHTTPRPS != 20 || tm.NmapPeakPPS != 720 || tm.ThrottleCount != 1 ||
		tm.Timeouts != 12 || tm.HTTP429 != 6 || len(tm.Throttles) != 1 || tm.Throttles[0].Reason != "http_429" || len(tm.WindowEvents) != 2 {
		t.Fatalf("telemetry: %+v", tm)
	}
}
