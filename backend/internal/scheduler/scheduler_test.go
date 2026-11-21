package scheduler

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// fakeRunner marks runs RUNNING (like the live runner) and records every start.
type fakeRunner struct {
	store  *db.MemoryStore
	mu     sync.Mutex
	starts []domain.ScanRun
}

func (f *fakeRunner) StartScan(ctx context.Context, run *domain.ScanRun, _ *domain.ScanProfile, _ []domain.TargetExclusion) error {
	run.Status = domain.ScanStatusRunning
	if err := f.store.UpdateScanRun(ctx, run); err != nil {
		return err
	}
	f.mu.Lock()
	f.starts = append(f.starts, *run)
	f.mu.Unlock()
	return nil
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.starts)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

var warsaw = func() *time.Location {
	loc, err := time.LoadLocation("Europe/Warsaw")
	if err != nil {
		return time.UTC
	}
	return loc
}()

func at(y int, m time.Month, d, hh, mm int) time.Time {
	return time.Date(y, m, d, hh, mm, 0, 0, warsaw)
}

func newEnv(t *testing.T, start time.Time) (*db.MemoryStore, *fakeRunner, *clock) {
	t.Helper()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	store := db.NewMemoryStore(vault)
	return store, &fakeRunner{store: store}, &clock{t: start}
}

func newSched(store *db.MemoryStore, r *fakeRunner, c *clock) *Scheduler {
	return New(store, r, Options{Now: c.Now, SyncStart: true, Logf: func(string, ...any) {}})
}

func addProfile(t *testing.T, store *db.MemoryStore, p domain.ScanProfile) domain.ScanProfile {
	t.Helper()
	if p.Name == "" {
		p.Name = "nightly"
	}
	if len(p.Targets) == 0 {
		p.Targets = []string{"10.0.0.0/24"}
	}
	if p.Timezone == "" {
		p.Timezone = "Europe/Warsaw"
	}
	p.Enabled = true
	if err := store.CreateProfile(context.Background(), &p); err != nil {
		t.Fatalf("create profile: %v", err)
	}
	return p
}

func setRunStatus(t *testing.T, store *db.MemoryStore, id, status string) {
	t.Helper()
	ctx := context.Background()
	run, err := store.GetScanRun(ctx, id)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	run.Status = status
	if status == domain.ScanStatusCompleted {
		f := run.StartedAt.Add(time.Hour)
		run.FinishedAt = &f
	}
	if err := store.UpdateScanRun(ctx, run); err != nil {
		t.Fatalf("update run: %v", err)
	}
}

func TestCronFiresOnceAtSlot(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 21, 0))
	addProfile(t, store, domain.ScanProfile{ScheduleCron: "0 22 * * *"})
	s := newSched(store, runner, clk)

	s.Tick(ctx) // 21:00 - registers the schedule, nothing due
	clk.Set(at(2026, 11, 20, 21, 59))
	s.Tick(ctx)
	if runner.count() != 0 {
		t.Fatalf("fired before slot: %d", runner.count())
	}
	clk.Set(at(2026, 11, 20, 22, 0).Add(15 * time.Second))
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("expected 1 fire at 22:00, got %d", runner.count())
	}
	if got := runner.starts[0].TriggeredBy; got != TriggeredByScheduler {
		t.Fatalf("triggered_by=%q", got)
	}
	clk.Set(at(2026, 11, 20, 22, 0).Add(45 * time.Second))
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("double fire within the same slot: %d", runner.count())
	}
	// Next day, previous run finished -> fires again.
	setRunStatus(t, store, runner.starts[0].ID, domain.ScanStatusCompleted)
	clk.Set(at(2026, 11, 21, 22, 0).Add(10 * time.Second))
	s.Tick(ctx)
	if runner.count() != 2 {
		t.Fatalf("expected 2nd daily fire, got %d", runner.count())
	}
}

func TestNewScheduleDoesNotRetroFire(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 23, 0)) // after today's 22:00 slot
	addProfile(t, store, domain.ScanProfile{ScheduleCron: "0 22 * * *"})
	s := newSched(store, runner, clk)
	s.Tick(ctx)
	if runner.count() != 0 {
		t.Fatalf("a freshly seen schedule must not fire for past slots, got %d", runner.count())
	}
}

func TestSlotOutsideWindowDefersToWindowOpen(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 11, 0))
	p := addProfile(t, store, domain.ScanProfile{
		ScheduleCron: "0 12 * * *", WindowEnabled: true, WindowStart: "22:00", WindowEnd: "06:00",
	})
	s := newSched(store, runner, clk)
	s.Tick(ctx)

	clk.Set(at(2026, 11, 20, 12, 0).Add(5 * time.Second))
	s.Tick(ctx)
	if runner.count() != 0 {
		t.Fatalf("must not start outside the window, got %d", runner.count())
	}
	st := s.Statuses(ctx, []domain.ScanProfile{p})[p.ID]
	if !st.PendingCatchUp || !st.DeferredByWindow || st.NextRunAt == nil || !st.NextRunAt.Equal(at(2026, 11, 20, 22, 0)) {
		t.Fatalf("expected deferred pending fire at 22:00, got %+v", st)
	}

	clk.Set(at(2026, 11, 20, 18, 0))
	s.Tick(ctx)
	if runner.count() != 0 {
		t.Fatalf("still outside window at 18:00")
	}
	clk.Set(at(2026, 11, 20, 22, 0).Add(20 * time.Second))
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("expected deferred fire at window open, got %d", runner.count())
	}
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("deferred fire must happen once, got %d", runner.count())
	}
}

func TestOvernightWindowFiresAfterMidnight(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 20, 0))
	p := addProfile(t, store, domain.ScanProfile{
		ScheduleCron: "30 2 * * *", WindowEnabled: true, WindowStart: "22:00", WindowEnd: "06:00",
	})
	s := newSched(store, runner, clk)
	s.Tick(ctx)
	st := s.Statuses(ctx, []domain.ScanProfile{p})[p.ID]
	if st.DeferredByWindow || st.NextRunAt == nil || !st.NextRunAt.Equal(at(2026, 11, 21, 2, 30)) {
		t.Fatalf("02:30 is inside 22:00-06:00, expected next run 02:30 not deferred, got %+v", st)
	}
	clk.Set(at(2026, 11, 21, 2, 30).Add(10 * time.Second))
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("expected fire at 02:30 inside overnight window, got %d", runner.count())
	}
}

func TestNoConcurrentRunSkipsAndRecordsReason(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 21, 0))
	p := addProfile(t, store, domain.ScanProfile{ScheduleCron: "0 22 * * *"})
	s := newSched(store, runner, clk)
	s.Tick(ctx)
	clk.Set(at(2026, 11, 20, 22, 1))
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("expected first fire")
	}
	first := runner.starts[0].ID

	// The run overran the window and is parked as PAUSED_WINDOW: next slot must be skipped.
	setRunStatus(t, store, first, domain.ScanStatusPausedWindow)
	clk.Set(at(2026, 11, 21, 22, 1))
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("started a second concurrent run of the same profile")
	}
	st := s.Statuses(ctx, []domain.ScanProfile{p})[p.ID]
	if st.LastSkipAt == nil || !strings.Contains(st.LastSkipReason, first) || !strings.Contains(st.LastSkipReason, domain.ScanStatusPausedWindow) {
		t.Fatalf("expected recorded skip reason naming the blocking run, got %+v", st)
	}
	if st.ActiveRun == nil || st.ActiveRun.ID != first || !st.WillSkip {
		t.Fatalf("expected active run in status, got %+v", st)
	}
	// The skipped slot is consumed: no surprise start later the same night.
	clk.Set(at(2026, 11, 21, 23, 0))
	setRunStatus(t, store, first, domain.ScanStatusCompleted)
	s.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("skipped slot must not fire later, got %d", runner.count())
	}

	// Run-now is refused while a run is active.
	setRunStatus(t, store, first, domain.ScanStatusRunning)
	_, err := s.RunNow(ctx, p.ID, "analyst")
	var busy *BusyError
	if !errors.As(err, &busy) || !errors.Is(err, ErrProfileBusy) || busy.Run.ID != first {
		t.Fatalf("expected BusyError for run-now, got %v", err)
	}
	setRunStatus(t, store, first, domain.ScanStatusCompleted)
	run, err := s.RunNow(ctx, p.ID, "analyst")
	if err != nil || run.TriggeredBy != "analyst" || runner.count() != 2 {
		t.Fatalf("run-now after completion: run=%+v err=%v starts=%d", run, err, runner.count())
	}
}

func TestRestartCatchUpAtMostOnce(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 16, 21, 0))
	p := addProfile(t, store, domain.ScanProfile{
		ScheduleCron: "0 22 * * *", WindowEnabled: true, WindowStart: "22:00", WindowEnd: "06:00",
	})
	s1 := newSched(store, runner, clk)
	s1.Tick(ctx)
	clk.Set(at(2026, 11, 16, 22, 0).Add(10 * time.Second))
	s1.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("expected initial fire")
	}
	setRunStatus(t, store, runner.starts[0].ID, domain.ScanStatusCompleted)

	// Server down for 3 nights; boots at noon (window closed): one catch-up, deferred.
	clk.Set(at(2026, 11, 20, 12, 0))
	s2 := newSched(store, runner, clk) // fresh process, state comes from the store
	s2.Tick(ctx)
	if runner.count() != 1 {
		t.Fatalf("catch-up must wait for the window, got %d", runner.count())
	}
	st := s2.Statuses(ctx, []domain.ScanProfile{p})[p.ID]
	if !st.PendingCatchUp || !st.DeferredByWindow {
		t.Fatalf("expected pending deferred catch-up, got %+v", st)
	}
	clk.Set(at(2026, 11, 20, 22, 0).Add(30 * time.Second))
	s2.Tick(ctx)
	clk.Set(at(2026, 11, 20, 22, 1))
	s2.Tick(ctx)
	if runner.count() != 2 {
		t.Fatalf("expected exactly one catch-up for 4 missed slots, got %d starts", runner.count())
	}

	// Boot inside the window with a missed slot: catch up immediately, once.
	setRunStatus(t, store, runner.starts[1].ID, domain.ScanStatusCompleted)
	clk.Set(at(2026, 11, 23, 23, 30))
	s3 := newSched(store, runner, clk)
	s3.Tick(ctx)
	s3.Tick(ctx)
	if runner.count() != 3 {
		t.Fatalf("expected one immediate catch-up inside the window, got %d", runner.count())
	}
}

func TestCronChangeResetsAnchor(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 10, 0))
	p := addProfile(t, store, domain.ScanProfile{ScheduleCron: "0 22 * * *"})
	s := newSched(store, runner, clk)
	s.Tick(ctx)
	clk.Set(at(2026, 11, 20, 15, 0))
	p.ScheduleCron = "0 11 * * *" // 11:00 already passed today
	if err := store.UpdateProfile(ctx, &p); err != nil {
		t.Fatal(err)
	}
	s.Tick(ctx)
	if runner.count() != 0 {
		t.Fatalf("changing cron must not fire for past slots of the new expression")
	}
}

func TestDisabledOrInvalidProfilesNeverFire(t *testing.T) {
	ctx := context.Background()
	store, runner, clk := newEnv(t, at(2026, 11, 20, 21, 0))
	bad := addProfile(t, store, domain.ScanProfile{Name: "bad", ScheduleCron: "every night"})
	off := addProfile(t, store, domain.ScanProfile{Name: "off", ScheduleCron: "* * * * *"})
	off.Enabled = false
	_ = store.UpdateProfile(ctx, &off)
	s := newSched(store, runner, clk)
	s.Tick(ctx)
	clk.Set(at(2026, 11, 21, 21, 0))
	s.Tick(ctx)
	if runner.count() != 0 {
		t.Fatalf("disabled/invalid profiles fired %d times", runner.count())
	}
	st := s.Statuses(ctx, []domain.ScanProfile{bad})[bad.ID]
	if st.CronError == "" || st.Scheduled {
		t.Fatalf("expected cron error in status, got %+v", st)
	}
}

func TestValidateCron(t *testing.T) {
	valid := []string{"", "0 22 * * *", "*/15 22-23,0-5 * * 1-5", "@daily", "0 2 * * SUN"}
	for _, v := range valid {
		if err := ValidateCron(v); err != nil {
			t.Errorf("ValidateCron(%q) unexpected error: %v", v, err)
		}
	}
	invalid := []string{"0 22 * *", "0 0 22 * * *", "61 * * * *", "@every 5m", "CRON_TZ=UTC 0 22 * * *", "nightly"}
	for _, v := range invalid {
		err := ValidateCron(v)
		if err == nil || !strings.Contains(err.Error(), "invalid schedule_cron") {
			t.Errorf("ValidateCron(%q) expected clear error, got %v", v, err)
		}
	}
}

func TestStatusUsesProfileTimezoneAndDST(t *testing.T) {
	p := domain.ScanProfile{ID: "p", ScheduleCron: "0 22 * * *", Timezone: "Europe/Warsaw", Enabled: true}
	// 2026-10-24 is the last day of CEST; 22:00 Warsaw = 20:00 UTC, next day (CET) = 21:00 UTC.
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	st := ComputeStatus(p, nil, nil, now)
	if st.NextRunAt == nil || !st.NextRunAt.Equal(time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC)) {
		t.Fatalf("CEST next run wrong: %+v", st.NextRunAt)
	}
	now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	st = ComputeStatus(p, nil, nil, now)
	if st.NextRunAt == nil || !st.NextRunAt.Equal(time.Date(2026, 10, 25, 21, 0, 0, 0, time.UTC)) {
		t.Fatalf("CET next run wrong: %+v", st.NextRunAt)
	}
}
