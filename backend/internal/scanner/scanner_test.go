package scanner

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type mockResolver struct {
	records map[string][]string
}

func (m mockResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return m.records[host], nil
}

func TestSlash16ExpansionAndStrictExclusionGate(t *testing.T) {
	resolver := mockResolver{
		records: map[string][]string{
			"portal.agh.edu.pl": {"10.10.0.5", "10.10.1.10"},
			"denied.agh.edu.pl": {"10.10.2.50"},
		},
	}

	exclusions := []domain.TargetExclusion{
		{ID: "ex-1", Value: "10.10.1.0/24", Reason: "Restricted subnet"},
		{ID: "ex-2", Value: "10.10.0.10-10.10.0.19", Reason: "Range exclusion"},
		{ID: "ex-3", Value: "10.10.0.5", Reason: "Single IP exclusion"},
		{ID: "ex-4", Value: "denied.agh.edu.pl", Reason: "Domain exclusion"},
	}

	start := time.Now()
	res, err := ParseAndNormalizeTargets(context.Background(), []string{
		"10.10.0.0/16",
		"10.10.0.1-10.10.0.20", // overlaps /16, must deduplicate!
		"portal.agh.edu.pl",    // maps to 10.10.0.5 (excluded) and 10.10.1.10 (excluded)
	}, exclusions, resolver)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ParseAndNormalizeTargets failed: %v", err)
	}

	// /16 = 65,536 total IPs.
	// Excluded: 256 (10.10.1.0/24) + 10 (10.10.0.10..19) + 1 (10.10.0.5) + 1 (10.10.2.50) = 268.
	if res.TotalCount != 65536 {
		t.Fatalf("TotalCount = %d, want 65536", res.TotalCount)
	}
	if res.ExcludedCount != 268 {
		t.Fatalf("ExcludedCount = %d, want 268", res.ExcludedCount)
	}
	if len(res.IPs) != 65536-268 {
		t.Fatalf("effective IPs = %d, want %d", len(res.IPs), 65536-268)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("/16 expansion too slow: %v", elapsed)
	}

	// Verify excluded IPs are strictly absent and domain map is scrubbed.
	for _, ip := range res.IPs {
		if ip == "10.10.0.5" || ip == "10.10.2.50" || strings.HasPrefix(ip, "10.10.1.") || ip == "10.10.0.15" {
			t.Fatalf("excluded IP %s leaked into effective targets!", ip)
		}
	}
	if _, exists := res.DomainToIPs["portal.agh.edu.pl"]; exists {
		t.Fatalf("excluded domain IPs should have been filtered from DomainToIPs")
	}

	// Verify non-excluded domain mapping preservation.
	res2, err := ParseAndNormalizeTargets(context.Background(), []string{"portal.agh.edu.pl"}, nil, resolver)
	if err != nil {
		t.Fatalf("ParseAndNormalizeTargets(domain) failed: %v", err)
	}
	if len(res2.DomainToIPs["portal.agh.edu.pl"]) != 2 || len(res2.IPToDomains["10.10.0.5"]) != 1 {
		t.Fatalf("domain mapping not preserved: %+v / %+v", res2.DomainToIPs, res2.IPToDomains)
	}
}

func TestOvernightWindowGuardWarsaw(t *testing.T) {
	wg, err := NewWindowGuard(true, "22:00", "06:00", "Europe/Warsaw")
	if err != nil {
		t.Fatalf("NewWindowGuard: %v", err)
	}
	loc := wg.Location

	// 23:30 Warsaw -> OPEN, remaining 6h30m.
	tOpenLate := time.Date(2026, 5, 10, 23, 30, 0, 0, loc)
	if !wg.IsOpen(tOpenLate) {
		t.Fatalf("23:30 should be inside 22:00-06:00 window")
	}
	if rem := wg.Remaining(tOpenLate); rem != 6*time.Hour+30*time.Minute {
		t.Fatalf("Remaining(23:30) = %v, want 6h30m", rem)
	}

	// 02:15 Warsaw -> OPEN, remaining 3h45m.
	tOpenEarly := time.Date(2026, 5, 11, 2, 15, 0, 0, loc)
	if !wg.IsOpen(tOpenEarly) {
		t.Fatalf("02:15 should be inside 22:00-06:00 window")
	}
	if rem := wg.Remaining(tOpenEarly); rem != 3*time.Hour+45*time.Minute {
		t.Fatalf("Remaining(02:15) = %v, want 3h45m", rem)
	}

	// 12:00 Warsaw -> CLOSED, NextOpen is today at 22:00.
	tClosed := time.Date(2026, 5, 11, 12, 0, 0, 0, loc)
	if wg.IsOpen(tClosed) {
		t.Fatalf("12:00 should be outside 22:00-06:00 window")
	}
	if rem := wg.Remaining(tClosed); rem != 0 {
		t.Fatalf("Remaining(12:00) = %v, want 0", rem)
	}
	next := wg.NextOpen(tClosed)
	wantNext := time.Date(2026, 5, 11, 22, 0, 0, 0, loc)
	if !next.Equal(wantNext) {
		t.Fatalf("NextOpen(12:00) = %v, want %v", next, wantNext)
	}

	// FitsInWindow check: 8h window = 28800s.
	if !wg.FitsInWindow(tClosed, 7*3600) {
		t.Fatalf("7h scan should fit in 8h window")
	}
	if wg.FitsInWindow(tClosed, 9*3600) {
		t.Fatalf("9h scan should NOT fit in single 8h window")
	}
	if wg.EstimatedWindows(9*3600) != 2 {
		t.Fatalf("EstimatedWindows(9h) = %d, want 2", wg.EstimatedWindows(9*3600))
	}
}

func TestNoiseGovernorDynamicBackoffAndThrottleCallback(t *testing.T) {
	var mu sync.Mutex
	var events []ThrottleEvent

	now := time.Date(2026, 5, 10, 10, 0, 0, 0, time.UTC)
	gov := NewGovernor(GovernorConfig{
		GlobalRatePerSec:  100,
		PerHostRatePerSec: 20,
		MinRatePerSec:     10,
		ErrorThreshold:    4,
		ErrorWindow:       10 * time.Second,
		CooldownDuration:  5 * time.Second,
		BackoffFactor:     0.5,
		Now:               func() time.Time { return now },
		OnThrottle: func(te ThrottleEvent) {
			mu.Lock()
			events = append(events, te)
			mu.Unlock()
		},
	})

	// Trigger timeout burst (4 timeouts -> rate halves from 100 -> 50).
	for i := 0; i < 4; i++ {
		gov.RecordTimeout("10.0.0.1")
	}
	if got := gov.CurrentRate(); got != 50 {
		t.Fatalf("after timeout burst rate = %.1f, want 50.0", got)
	}

	// Trigger HTTP 429 burst (each 429 has weight 2 -> 2x 429 triggers backoff 50 -> 25).
	gov.RecordHTTPStatus("10.0.0.1", 429)
	gov.RecordHTTPStatus("10.0.0.1", 429)
	if got := gov.CurrentRate(); got != 25 {
		t.Fatalf("after 429 burst rate = %.1f, want 25.0", got)
	}

	mu.Lock()
	evCount := len(events)
	mu.Unlock()
	if evCount != 2 {
		t.Fatalf("expected 2 throttle callbacks, got %d", evCount)
	}

	// Advance past cooldown and record healthy responses -> gradual AIMD recovery.
	now = now.Add(6 * time.Second)
	for i := 0; i < 10; i++ {
		gov.RecordSuccess("10.0.0.1")
	}
	if got := gov.CurrentRate(); got <= 25 {
		t.Fatalf("expected rate recovery > 25, got %.1f", got)
	}
}

func TestExactOvernightWindowPauseAndResume(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	if loc == nil {
		loc = time.UTC
	}

	var mu sync.Mutex
	curTime := time.Date(2026, 5, 11, 5, 58, 0, 0, loc) // 2 minutes before 06:00 close!
	nowFn := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return curTime
	}
	advanceTime := func(d time.Duration) {
		mu.Lock()
		curTime = curTime.Add(d)
		mu.Unlock()
	}

	var scannedChunks []int
	eng := NewEngine(EngineConfig{
		UseNmap: false,
		Now:     nowFn,
		// Sequential worker: this test pins the chunk-boundary semantics (see
		// engine_concurrency_test.go for the concurrent pause/resume variant).
		MaxChunkWorkers:         1,
		DisableAdaptiveChunking: true,
		CustomDiscoveryFn: func(ctx context.Context, ips []string) ([]string, error) {
			// Simulate chunk taking 3 minutes -> after chunk 0 finishes, clock is 06:01 (window CLOSED!).
			advanceTime(3 * time.Minute)
			return ips[:1], nil
		},
		CustomServiceScanFn: func(ctx context.Context, activeIPs []string, ports []int) (map[string][]domain.ObservedService, string, error) {
			m := make(map[string][]domain.ObservedService)
			for _, ip := range activeIPs {
				m[ip] = []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"}}
			}
			return m, GenerateNmapXML([]domain.ObservedHost{{IP: activeIPs[0], IsAlive: true, Services: m[activeIPs[0]]}}, "", nowFn(), nowFn()), nil
		},
	})

	profile := domain.ScanProfile{
		ID:                    "prof-1",
		Name:                  "Night Window Scan",
		Targets:               []string{"10.20.0.0/25"}, // 128 IPs -> 4 chunks of 32
		AllowedPorts:          "80,443",
		MaxRatePPS:            100,
		Concurrency:           16,
		ChunkTargetSec:        1,
		WindowEnabled:         true,
		WindowStart:           "22:00",
		WindowEnd:             "06:00",
		Timezone:              "Europe/Warsaw",
		EnableHTTPFingerprint: false,
	}

	run, res, err := eng.PrepareRun(context.Background(), "run-win-1", profile, nil)
	if err != nil {
		t.Fatalf("PrepareRun: %v", err)
	}
	// Force 4 deterministic chunks of 32 IPs.
	run.Chunks = BuildChunks(run.ID, res.IPs, 32)
	run.TotalChunks = len(run.Chunks)

	var pausedEvents int
	cb := RunCallbacks{
		OnEvent: func(ev domain.LiveEvent) {
			if ev.Type == "scan.paused_window" {
				pausedEvents++
			}
		},
		OnChunkUpdate: func(ch domain.ScanChunk) {
			if ch.Status == domain.ChunkStatusDone {
				scannedChunks = append(scannedChunks, ch.ChunkIndex)
			}
		},
	}

	// Pass 1: runs chunk 0 (05:58 -> 06:01), then pauses cleanly at chunk 1 boundary!
	r1, err := eng.Execute(context.Background(), run, profile, res, cb)
	if err != nil {
		t.Fatalf("Execute pass 1: %v", err)
	}
	if !r1.PausedByWindow || run.Status != domain.ScanStatusPausedWindow {
		t.Fatalf("expected PAUSED_WINDOW after chunk 0, got status=%s paused=%v", run.Status, r1.PausedByWindow)
	}
	if run.CompletedChunks != 1 || run.Chunks[0].Status != domain.ChunkStatusDone || run.Chunks[1].Status != domain.ChunkStatusPending {
		t.Fatalf("unexpected chunk states after pause: completed=%d c0=%s c1=%s", run.CompletedChunks, run.Chunks[0].Status, run.Chunks[1].Status)
	}
	if pausedEvents != 1 {
		t.Fatalf("expected 1 scan.paused_window event, got %d", pausedEvents)
	}

	// Pass 2: clock jumps to next night window (22:05) -> resumes from chunk 1, skips chunk 0!
	mu.Lock()
	curTime = time.Date(2026, 5, 11, 22, 5, 0, 0, loc)
	mu.Unlock()

	r2, err := eng.Execute(context.Background(), run, profile, res, cb)
	if err != nil {
		t.Fatalf("Execute pass 2: %v", err)
	}
	if r2.PausedByWindow || run.Status != domain.ScanStatusCompleted {
		t.Fatalf("expected COMPLETED on resume, got status=%s", run.Status)
	}
	if run.CompletedChunks != 4 || len(scannedChunks) != 4 {
		t.Fatalf("expected exact 4 chunks completed without duplicating chunk 0, got completed=%d scanned=%v", run.CompletedChunks, scannedChunks)
	}
	if !run.HasRawNmapXML || !strings.Contains(r2.RawNmapXML, "<nmaprun") {
		t.Fatalf("expected aggregated RawNmapXML across resumed windows")
	}
}

func TestEngineEndToEndWithLocalHTTPServerAndUnstableReprobe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.1")
		_, _ = w.Write([]byte(`<title>Aegis Lab Service</title>`))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// Test Stage 4 unstable re-probe: simulate host failing Stage 1 once, then responding on re-probe!
	var discoverCalls atomic.Int32
	eng := NewEngine(EngineConfig{
		UseNmap:       false,
		UnstableHosts: []string{host},
		CustomDiscoveryFn: func(ctx context.Context, ips []string) ([]string, error) {
			n := discoverCalls.Add(1)
			if n == 1 {
				return nil, nil // missed on initial Stage 1!
			}
			return ips, nil // recovered on Stage 4 re-probe!
		},
	})

	profile := domain.ScanProfile{
		ID:                    "prof-local",
		Name:                  "Local Lab",
		Targets:               []string{host},
		AllowedPorts:          strconv.Itoa(port),
		MaxRatePPS:            200,
		HTTPRPS:               50,
		Concurrency:           4,
		RetryUnstableCount:    2,
		EnableHTTPFingerprint: true,
	}

	run, res, err := eng.PrepareRun(context.Background(), "run-lab-1", profile, nil)
	if err != nil {
		t.Fatalf("PrepareRun: %v", err)
	}

	out, err := eng.Execute(context.Background(), run, profile, res, RunCallbacks{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if discoverCalls.Load() < 2 {
		t.Fatalf("expected Stage 4 unstable host re-probe to run (>= 2 discovery calls), got %d", discoverCalls.Load())
	}
	if len(out.ObservedHosts) != 1 || !out.ObservedHosts[0].IsAlive {
		t.Fatalf("expected host recovered via Stage 4 re-probe, got %+v", out.ObservedHosts)
	}
	if len(out.ObservedHosts[0].Services) != 1 {
		t.Fatalf("expected 1 open service on port %d, got %+v", port, out.ObservedHosts[0].Services)
	}
	svc := out.ObservedHosts[0].Services[0]
	if svc.HTTP == nil || svc.HTTP.Title != "Aegis Lab Service" {
		t.Fatalf("expected Stage 3 HTTP fingerprint title 'Aegis Lab Service', got %+v", svc.HTTP)
	}
	if out.RawNmapXML == "" {
		t.Fatalf("expected non-empty Nmap XML from pure-Go fallback")
	}

	// Verify ParseNmapXML roundtrip on generated XML.
	parsed, err := ParseNmapXML([]byte(out.RawNmapXML))
	if err != nil {
		t.Fatalf("ParseNmapXML failed: %v", err)
	}
	if len(parsed) != 1 || len(parsed[0].Services) != 1 || parsed[0].Services[0].Port != port {
		t.Fatalf("ParseNmapXML roundtrip mismatch: %+v", parsed)
	}
}
