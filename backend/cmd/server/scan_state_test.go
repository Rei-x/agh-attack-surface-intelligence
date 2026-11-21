package main

import (
	"context"
	"errors"
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
)

// slowRunner returns a LiveScanRunner whose fake engine takes ~30 ms per chunk and counts
// concurrently running discovery calls (must never exceed the worker limit).
func slowRunner(t *testing.T) (*LiveScanRunner, db.Store, *atomic.Int32) {
	t.Helper()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	hub := api.NewSSEHub()
	pipeline := ingest.NewPipeline(store, NewIntelligenceAnalyzer(), hub.Publish)
	runner := NewLiveScanRunner(store, pipeline, hub)
	var inFlight, maxInFlight atomic.Int32
	runner.engineConfig = func(cfg scanner.EngineConfig) scanner.EngineConfig {
		cfg.UseNmap = false
		cfg.MaxChunkWorkers = 1
		cfg.DisableAdaptiveChunking = true
		cfg.CustomDiscoveryFn = func(ctx context.Context, ips []string) ([]string, error) {
			n := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				m := maxInFlight.Load()
				if n <= m || maxInFlight.CompareAndSwap(m, n) {
					break
				}
			}
			select {
			case <-time.After(30 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return ips[:1], nil
		}
		cfg.CustomServiceScanFn = func(ctx context.Context, ips []string, ports []int) (map[string][]domain.ObservedService, string, error) {
			m := map[string][]domain.ObservedService{}
			for _, ip := range ips {
				m[ip] = []domain.ObservedService{{Port: 22, Protocol: "tcp", State: "open"}}
			}
			return m, "", nil
		}
		return cfg
	}
	return runner, store, &maxInFlight
}

func startAdhoc(t *testing.T, runner *LiveScanRunner, store db.Store) *domain.ScanRun {
	t.Helper()
	ctx := context.Background()
	profile := &domain.ScanProfile{Name: "quick", Targets: []string{"10.81.0.0/27"}, AllowedPorts: "22",
		MaxRatePPS: 100, Concurrency: 4, ChunkTargetSec: 1, MissingThreshold: 2, GracePeriodHours: 24}
	run := &domain.ScanRun{ID: db.NewID(), Name: "quick", RunType: domain.ScanTypeActive, Status: domain.ScanStatusQueued, StartedAt: time.Now().UTC()}
	if err := store.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := runner.StartScan(ctx, run, profile, nil); err != nil {
		t.Fatal(err)
	}
	return run
}

func TestQuickScanPauseResumeAndInvalidTransitions(t *testing.T) {
	ctx := context.Background()
	runner, store, maxInFlight := slowRunner(t)
	run := startAdhoc(t, runner, store)
	waitStatus(t, store, run.ID, domain.ScanStatusRunning)

	if err := runner.PauseScan(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	// Double-click resume: exactly one succeeds, the other is a clean conflict.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs[i] = runner.ResumeScan(ctx, run.ID) }(i)
	}
	wg.Wait()
	ok, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, db.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected resume error: %v", err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("double resume: ok=%d conflicts=%d (%v)", ok, conflicts, errs)
	}
	waitIdle(t, runner, run.ID)
	done := waitStatus(t, store, run.ID, domain.ScanStatusCompleted)
	if done.CompletedChunks != done.TotalChunks {
		t.Fatalf("resumed quick scan did not finish all chunks: %d/%d", done.CompletedChunks, done.TotalChunks)
	}
	if maxInFlight.Load() > 1 {
		t.Fatalf("two workers ran concurrently (max in flight %d)", maxInFlight.Load())
	}
	for name, op := range map[string]func(context.Context, string) error{
		"pause": runner.PauseScan, "resume": runner.ResumeScan, "stop": runner.StopScan,
	} {
		if err := op(ctx, run.ID); !errors.Is(err, db.ErrConflict) {
			t.Errorf("%s on a COMPLETED run: want conflict, got %v", name, err)
		}
	}
	if r, _ := store.GetScanRun(ctx, run.ID); r.Status != domain.ScanStatusCompleted {
		t.Fatalf("completed run was modified: %s", r.Status)
	}
}

func TestQuickScanPausedBeforeRestartGivesClearError(t *testing.T) {
	ctx := context.Background()
	runner, store, _ := slowRunner(t)
	run := startAdhoc(t, runner, store)
	waitStatus(t, store, run.ID, domain.ScanStatusRunning)
	if err := runner.PauseScan(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, runner, run.ID)
	fresh := NewLiveScanRunner(store, nil, nil) // "after restart": no in-memory quick-scan profile
	err := fresh.ResumeScan(ctx, run.ID)
	if !errors.Is(err, db.ErrConflict) {
		t.Fatalf("want a clear conflict, got %v", err)
	}
}
