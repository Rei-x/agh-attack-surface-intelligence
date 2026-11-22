package main

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scheduler"
)

func waitIdle(t *testing.T, r *LiveScanRunner, runID string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for r.IsScanActive(runID) {
		if time.Now().After(deadline) {
			t.Fatalf("run %s still active", runID)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitStatus(t *testing.T, store db.Store, runID string, want ...string) *domain.ScanRun {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		run, err := store.GetScanRun(context.Background(), runID)
		if err == nil {
			for _, w := range want {
				if run.Status == w {
					return run
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	run, _ := store.GetScanRun(context.Background(), runID)
	t.Fatalf("run %s did not reach %v (status=%v)", runID, want, run)
	return nil
}

// TestWindowOverrunPausesAndResumesEndToEnd drives the real LiveScanRunner + ingest pipeline +
// scheduler run-now through: full scan -> second scan overruns the 22:00-06:00 window at
// 06:00 -> PAUSED_WINDOW with checkpoint -> window watcher resumes at 22:01 -> COMPLETED.
// Hosts scanned in the first window must not be flagged missing by the resumed segment, and
// the profile must be blocked from a concurrent run while paused.
func TestWindowOverrunPausesAndResumesEndToEnd(t *testing.T) {
	ctx := context.Background()
	loc, _ := time.LoadLocation("Europe/Warsaw")
	if loc == nil {
		loc = time.UTC
	}
	var clockMu sync.Mutex
	cur := time.Date(2026, 11, 19, 23, 0, 0, 0, loc)
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return cur }
	advance := func(d time.Duration) { clockMu.Lock(); cur = cur.Add(d); clockMu.Unlock() }
	set := func(t time.Time) { clockMu.Lock(); cur = t; clockMu.Unlock() }

	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewMemoryStore(vault)
	hub := api.NewSSEHub()
	pipeline := ingest.NewPipeline(store, NewIntelligenceAnalyzer(), hub.Publish)
	runner := NewLiveScanRunner(store, pipeline, hub)
	runner.nowFn = now

	var tickClock atomic.Bool // advance 1 min per discovery call (second scan only)
	runner.engineConfig = func(cfg scanner.EngineConfig) scanner.EngineConfig {
		cfg.UseNmap = false
		cfg.MaxChunkWorkers = 1
		cfg.DisableAdaptiveChunking = true
		cfg.WindowPollInterval = 5 * time.Millisecond
		cfg.CustomDiscoveryFn = func(ctx context.Context, ips []string) ([]string, error) {
			if tickClock.Load() {
				advance(time.Minute)
			}
			return ips[:1], nil // first IP of every chunk is alive
		}
		cfg.CustomServiceScanFn = func(ctx context.Context, ips []string, ports []int) (map[string][]domain.ObservedService, string, error) {
			m := map[string][]domain.ObservedService{}
			var hosts []domain.ObservedHost
			for _, ip := range ips {
				m[ip] = []domain.ObservedService{{Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh", Product: "OpenSSH", Version: "9.6"}}
				hosts = append(hosts, domain.ObservedHost{IP: ip, IsAlive: true, Services: m[ip]})
			}
			return m, scanner.GenerateNmapXML(hosts, "", now(), now()), nil
		}
		return cfg
	}

	profile := &domain.ScanProfile{
		Name: "night", Targets: []string{"10.70.0.0/24"}, AllowedPorts: "22", MaxRatePPS: 100,
		Concurrency: 8, ChunkTargetSec: 1, WindowEnabled: true, WindowStart: "22:00", WindowEnd: "06:00",
		Timezone: "Europe/Warsaw", MissingThreshold: 2, GracePeriodHours: 24, Enabled: true,
	}
	if err := store.CreateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	sched := scheduler.New(store, runner, scheduler.Options{Now: now, SyncStart: true, Logf: t.Logf})

	// Scan 1: completes inside the window, establishes 8 active hosts.
	run1, err := sched.RunNow(ctx, profile.ID, "analyst")
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, store, run1.ID, domain.ScanStatusRunning, domain.ScanStatusCompleted)
	waitIdle(t, runner, run1.ID)
	done1 := waitStatus(t, store, run1.ID, domain.ScanStatusCompleted)
	if done1.TotalChunks != 8 || done1.ActiveHosts != 8 {
		t.Fatalf("scan 1: chunks=%d active=%d", done1.TotalChunks, done1.ActiveHosts)
	}

	// Scan 2 starts 05:57; each chunk takes 1 (fake) minute -> window closes after chunk 3.
	set(time.Date(2026, 11, 20, 5, 57, 0, 0, loc))
	tickClock.Store(true)
	run2, err := sched.RunNow(ctx, profile.ID, "analyst")
	if err != nil {
		t.Fatal(err)
	}
	waitIdle(t, runner, run2.ID) // segment goroutine finished ingesting
	paused := waitStatus(t, store, run2.ID, domain.ScanStatusPausedWindow)
	if paused.CompletedChunks != 3 || paused.WindowPausedCount != 1 || paused.FinishedAt != nil {
		t.Fatalf("paused checkpoint wrong: completed=%d pausedCnt=%d finished=%v", paused.CompletedChunks, paused.WindowPausedCount, paused.FinishedAt)
	}
	chunks, _ := store.GetScanChunks(ctx, run2.ID)
	pending := 0
	for _, ch := range chunks {
		if ch.Status == domain.ChunkStatusPending {
			pending++
		}
	}
	if pending != 5 {
		t.Fatalf("expected 5 pending chunks in checkpoint, got %d", pending)
	}
	// Window still closed: watcher must not resume; scheduler must refuse a parallel run.
	runner.checkPausedWindowScans(ctx)
	if r := waitStatus(t, store, run2.ID, domain.ScanStatusPausedWindow); r.CompletedChunks != 3 {
		t.Fatalf("resumed while window closed")
	}
	if _, err := sched.RunNow(ctx, profile.ID, "analyst"); err == nil {
		t.Fatalf("run-now must be refused while a run is PAUSED_WINDOW")
	}

	// Next window: watcher resumes from the checkpoint.
	tickClock.Store(false)
	set(time.Date(2026, 11, 20, 22, 1, 0, 0, loc))
	runner.checkPausedWindowScans(ctx)
	waitStatus(t, store, run2.ID, domain.ScanStatusRunning, domain.ScanStatusCompleted)
	waitIdle(t, runner, run2.ID)
	final := waitStatus(t, store, run2.ID, domain.ScanStatusCompleted)
	if final.CompletedChunks != 8 || final.ScannedIPs != 256 || final.ActiveHosts != 8 || !final.HasRawNmapXML {
		t.Fatalf("resumed scan incomplete: %+v", final)
	}
	chunks, _ = store.GetScanChunks(ctx, run2.ID)
	for _, ch := range chunks {
		if ch.Status != domain.ChunkStatusDone {
			t.Fatalf("chunk %d status %s", ch.ChunkIndex, ch.Status)
		}
	}
	for i := 0; i < 8; i++ {
		ip := "10.70.0." + strconv.Itoa(i*32) // the alive IP of chunk i
		h, err := store.GetHostByIP(ctx, ip)
		if err != nil {
			t.Fatalf("host %s: %v", ip, err)
		}
		if h.ConsecutiveMisses != 0 || h.LifecycleState == domain.HostStateMissing || h.LifecycleState == domain.HostStateInactive {
			t.Fatalf("host %s wrongly marked missing after resumed scan: state=%s misses=%d", h.IP, h.LifecycleState, h.ConsecutiveMisses)
		}
	}
}

func TestRecoverInterruptedParksOrphanedRuns(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	runner := NewLiveScanRunner(store, nil, nil)

	withLedger := &domain.ScanRun{ID: "orphan-1", ProfileID: "p1", Name: "o1", RunType: domain.ScanTypeActive, Status: domain.ScanStatusRunning, StartedAt: time.Now().UTC()}
	noLedger := &domain.ScanRun{ID: "orphan-2", ProfileID: "p1", Name: "o2", RunType: domain.ScanTypeActive, Status: domain.ScanStatusQueued, StartedAt: time.Now().UTC()}
	finished := &domain.ScanRun{ID: "done-1", ProfileID: "p1", Name: "d", RunType: domain.ScanTypeActive, Status: domain.ScanStatusCompleted, StartedAt: time.Now().UTC()}
	for _, r := range []*domain.ScanRun{withLedger, noLedger, finished} {
		if err := store.CreateScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	started := time.Now().UTC()
	_ = store.SaveScanChunks(ctx, "orphan-1", []domain.ScanChunk{
		{ID: "c0", ChunkIndex: 0, Status: domain.ChunkStatusDone},
		{ID: "c1", ChunkIndex: 1, Status: domain.ChunkStatusRunning, StartedAt: &started},
	})

	n, err := runner.RecoverInterrupted(ctx)
	if err != nil || n != 2 {
		t.Fatalf("recovered=%d err=%v", n, err)
	}
	r1, _ := store.GetScanRun(ctx, "orphan-1")
	r2, _ := store.GetScanRun(ctx, "orphan-2")
	r3, _ := store.GetScanRun(ctx, "done-1")
	if r1.Status != domain.ScanStatusPausedWindow || r2.Status != domain.ScanStatusFailed || r3.Status != domain.ScanStatusCompleted {
		t.Fatalf("statuses after recovery: %s %s %s", r1.Status, r2.Status, r3.Status)
	}
	if !strings.Contains(r2.Notes, "restart") {
		t.Fatalf("failed orphan must explain why in its notes, got %q", r2.Notes)
	}
	chunks, _ := store.GetScanChunks(ctx, "orphan-1")
	if chunks[0].Status != domain.ChunkStatusDone || chunks[1].Status != domain.ChunkStatusPending || chunks[1].StartedAt != nil {
		t.Fatalf("chunks after recovery: %+v", chunks)
	}
}
