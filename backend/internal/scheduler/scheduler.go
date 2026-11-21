// Package scheduler fires recurring scans from ScanProfile.ScheduleCron.
//
// Semantics (CBI AGH task, section 2: "konkretne przedziały czasowe uruchomienia oraz
// częstotliwość wykonywania skanów"):
//
//   - The cron expression (5-field) is evaluated in the profile's timezone.
//   - If the profile has a time window and a slot falls outside it, the fire is deferred to
//     the moment the window opens. Overnight windows (22:00-06:00) are supported.
//   - A profile never has two concurrent runs. If the previous run is still QUEUED/RUNNING or
//     paused (by window or by a user) when a slot becomes due, the slot is skipped and the
//     reason is recorded.
//   - Overruns are handled by the engine: when the window closes mid-scan the run is stopped
//     with a chunk checkpoint (PAUSED_WINDOW) and resumed by the window watcher in the next
//     window. That paused run blocks new slots until it completes (no pile-up).
//   - Restart-safe: the last consumed slot ("anchor") is persisted per profile. On boot,
//     all slots missed while the server was down collapse into AT MOST ONE catch-up run,
//     which still respects the window (deferred until it opens).
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// TriggeredByScheduler is the ScanRun.TriggeredBy value of cron-fired runs.
const TriggeredByScheduler = "scheduler"

// Store is the subset of db.Store the scheduler needs.
type Store interface {
	ListProfiles(ctx context.Context) ([]domain.ScanProfile, error)
	GetProfile(ctx context.Context, id string) (*domain.ScanProfile, error)
	ListScanRuns(ctx context.Context, limit int) ([]domain.ScanRun, error)
	CreateScanRun(ctx context.Context, run *domain.ScanRun) error
	UpdateScanRun(ctx context.Context, run *domain.ScanRun) error
	ListExclusions(ctx context.Context) ([]domain.TargetExclusion, error)
}

// Runner starts a prepared scan run (implemented by the live scan runner and api.ScanRunner).
type Runner interface {
	StartScan(ctx context.Context, run *domain.ScanRun, profile *domain.ScanProfile, exclusions []domain.TargetExclusion) error
}

// Optional runner extensions.
type interruptedRecoverer interface {
	RecoverInterrupted(ctx context.Context) (int, error)
}
type eventPublisher interface {
	PublishEvent(ev domain.LiveEvent)
}

// ErrProfileBusy is returned by RunNow when the profile already has an active run.
var ErrProfileBusy = errors.New("profile already has an active scan run")

// BusyError carries the run that blocks a new start.
type BusyError struct {
	Run domain.ScanRun
}

func (e *BusyError) Error() string {
	return fmt.Sprintf("profile already has an active scan run %s (%s, status %s)", e.Run.ID, e.Run.Name, e.Run.Status)
}
func (e *BusyError) Unwrap() error { return ErrProfileBusy }

// Options configures a Scheduler. Zero values are production defaults.
type Options struct {
	Now      func() time.Time
	Interval time.Duration // evaluation tick, default 30s
	// SyncStart runs Runner.StartScan inline instead of in a goroutine (tests).
	SyncStart bool
	Publish   func(domain.LiveEvent)
	Logf      func(format string, args ...any)
}

// Scheduler evaluates every profile's cron schedule on a fixed tick.
type Scheduler struct {
	store  Store
	runner Runner
	states db.ScheduleStateStore // optional persistence
	opts   Options

	mu      sync.Mutex // serializes Tick and RunNow: no double start for a profile
	loaded  bool
	cache   map[string]*domain.ScheduleState
	noticed map[string]string // profileID -> last logged deferral/cron error (log dedupe)
}

// New builds a Scheduler. If store implements db.ScheduleStateStore, state is persisted.
func New(store Store, runner Runner, opts Options) *Scheduler {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	if opts.Publish == nil {
		if p, ok := runner.(eventPublisher); ok {
			opts.Publish = p.PublishEvent
		}
	}
	s := &Scheduler{
		store:   store,
		runner:  runner,
		opts:    opts,
		cache:   make(map[string]*domain.ScheduleState),
		noticed: make(map[string]string),
	}
	if ss, ok := store.(db.ScheduleStateStore); ok {
		s.states = ss
	}
	return s
}

var defaultScheduler atomic.Pointer[Scheduler]

// Default returns the process-wide scheduler started by Start (nil if not started).
func Default() *Scheduler { return defaultScheduler.Load() }

// Start is the single hook for cmd/server: it recovers runs orphaned by a previous process,
// evaluates schedules once immediately (catch-up) and then every Interval until ctx ends.
func Start(ctx context.Context, store Store, runner Runner) *Scheduler {
	s := New(store, runner, Options{})
	defaultScheduler.Store(s)
	if rec, ok := runner.(interruptedRecoverer); ok {
		if n, err := rec.RecoverInterrupted(ctx); err != nil {
			s.opts.Logf("[WARN] scheduler: recovering interrupted scans failed: %v", err)
		} else if n > 0 {
			s.opts.Logf("[INFO] scheduler: recovered %d scan run(s) interrupted by the previous shutdown", n)
		}
	}
	go s.Run(ctx)
	return s
}

// Run ticks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	s.Tick(ctx)
	t := time.NewTicker(s.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick evaluates all profiles once at s.opts.Now().
func (s *Scheduler) Tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLoadedLocked(ctx)
	profiles, err := s.store.ListProfiles(ctx)
	if err != nil {
		s.opts.Logf("[WARN] scheduler: list profiles: %v", err)
		return
	}
	now := s.opts.Now()
	runs, _ := s.store.ListScanRuns(ctx, 500)
	for _, p := range profiles {
		s.evaluateLocked(ctx, p, now, runs)
	}
}

func (s *Scheduler) evaluateLocked(ctx context.Context, p domain.ScanProfile, now time.Time, runs []domain.ScanRun) {
	expr := strings.TrimSpace(p.ScheduleCron)
	if expr == "" || !p.Enabled {
		return
	}
	sched, err := ParseCron(expr)
	if err != nil {
		s.noticeOnce(p.ID, "cron:"+expr, "[WARN] scheduler: profile %s (%s) has invalid schedule_cron %q: %v", p.ID, p.Name, expr, err)
		return
	}
	st := s.stateLocked(p.ID)
	if st.AnchorAt == nil || st.Cron != expr {
		// First sighting of this schedule (or the expression changed): count slots from now,
		// never retro-fire slots that predate the schedule. Without persisted state, fall back
		// to the last scheduler-triggered run so a restart doesn't silently drop a missed slot.
		anchor := now
		if st.AnchorAt == nil && s.states == nil {
			if last := lastRunOf(runs, p.ID, true); last != nil && last.StartedAt.Before(now) {
				anchor = last.StartedAt
			}
		}
		st.Cron = expr
		st.AnchorAt = &anchor
		s.persistLocked(ctx, st)
	}

	loc := loadLocation(p.Timezone)
	slot := sched.Next(st.AnchorAt.In(loc))
	if slot.IsZero() || slot.After(now) {
		return
	}

	wg, err := scanner.NewWindowGuard(p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone)
	if err != nil {
		s.skipLocked(ctx, st, p, now, fmt.Sprintf("slot %s skipped: invalid time window: %v", fmtTime(slot, loc), err))
		return
	}
	if !wg.IsOpen(now) {
		open := wg.NextOpen(now)
		s.noticeOnce(p.ID, "defer:"+slot.String(), "[INFO] scheduler: profile %s (%s) slot %s is outside window %s-%s; deferred to %s",
			p.ID, p.Name, fmtTime(slot, loc), p.WindowStart, p.WindowEnd, fmtTime(open, loc))
		return
	}

	if active := activeRunOf(runs, p.ID); active != nil {
		s.skipLocked(ctx, st, p, now, fmt.Sprintf("slot %s skipped: previous run %s (%s) is still %s",
			fmtTime(slot, loc), active.ID, active.Name, active.Status))
		return
	}

	notes := fmt.Sprintf("Started automatically by the scheduler (cron %q, %s; slot %s)", expr, p.Timezone, fmtTime(slot, loc))
	run, err := s.launch(ctx, p, TriggeredByScheduler, notes, now)
	if err != nil {
		s.skipLocked(ctx, st, p, now, fmt.Sprintf("slot %s skipped: could not start scan: %v", fmtTime(slot, loc), err))
		return
	}
	st.AnchorAt = &now
	fired := now
	st.LastFireAt = &fired
	st.LastRunID = run.ID
	s.persistLocked(ctx, st)
	s.opts.Logf("[INFO] scheduler: fired profile %s (%s) for slot %s -> scan run %s", p.ID, p.Name, fmtTime(slot, loc), run.ID)
	s.publish(domain.LiveEvent{Type: "schedule.fired", ScanRunID: run.ID, Timestamp: now, Payload: map[string]any{
		"profile_id": p.ID, "profile_name": p.Name, "slot": slot.UTC().Format(time.RFC3339), "cron": expr,
	}})
}

func (s *Scheduler) skipLocked(ctx context.Context, st *domain.ScheduleState, p domain.ScanProfile, now time.Time, reason string) {
	consumed := now
	st.AnchorAt = &consumed
	skipped := now
	st.LastSkipAt = &skipped
	st.LastSkipReason = reason
	s.persistLocked(ctx, st)
	s.opts.Logf("[INFO] scheduler: profile %s (%s): %s", p.ID, p.Name, reason)
	s.publish(domain.LiveEvent{Type: "schedule.skipped", Timestamp: now, Payload: map[string]any{
		"profile_id": p.ID, "profile_name": p.Name, "reason": reason,
	}})
}

// RunNow starts the profile immediately (manual trigger). It refuses with *BusyError when the
// profile already has an active run. It does not consume the cron slot bookkeeping; if the
// window is closed the engine parks the run as PAUSED_WINDOW and it starts when it opens.
func (s *Scheduler) RunNow(ctx context.Context, profileID, triggeredBy string) (*domain.ScanRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.store.GetProfile(ctx, profileID)
	if err != nil {
		return nil, err
	}
	runs, err := s.store.ListScanRuns(ctx, 500)
	if err != nil {
		return nil, err
	}
	if active := activeRunOf(runs, p.ID); active != nil {
		return nil, &BusyError{Run: *active}
	}
	if strings.TrimSpace(triggeredBy) == "" {
		triggeredBy = "system"
	}
	return s.launch(ctx, *p, triggeredBy, "Started manually", s.opts.Now())
}

func (s *Scheduler) launch(ctx context.Context, p domain.ScanProfile, triggeredBy, notes string, now time.Time) (*domain.ScanRun, error) {
	if len(p.Targets) == 0 {
		return nil, errors.New("profile has no targets")
	}
	if s.runner == nil {
		return nil, errors.New("no scan runner configured")
	}
	loc := loadLocation(p.Timezone)
	run := &domain.ScanRun{
		ID:          db.NewID(),
		ProfileID:   p.ID,
		Name:        p.Name + " " + now.In(loc).Format("2006-01-02 15:04"),
		RunType:     domain.ScanTypeActive,
		Status:      domain.ScanStatusQueued,
		Notes:       notes,
		TriggeredBy: triggeredBy,
		StartedAt:   now.UTC(),
	}
	if err := s.store.CreateScanRun(ctx, run); err != nil {
		return nil, err
	}
	out := *run
	exclusions, _ := s.store.ListExclusions(ctx)
	profile := p
	start := func() {
		bg := context.Background()
		if err := s.runner.StartScan(bg, run, &profile, exclusions); err != nil {
			s.opts.Logf("[ERROR] scheduler: start scan %s for profile %s: %v", run.ID, profile.ID, err)
			failed := time.Now().UTC()
			run.Status = domain.ScanStatusFailed
			run.FinishedAt = &failed
			_ = s.store.UpdateScanRun(bg, run)
		}
	}
	if s.opts.SyncStart {
		start()
	} else {
		go start()
	}
	return &out, nil
}

func (s *Scheduler) ensureLoadedLocked(ctx context.Context) {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.states == nil {
		return
	}
	list, err := s.states.ListScheduleStates(ctx)
	if err != nil {
		s.opts.Logf("[WARN] scheduler: load persisted state: %v", err)
		return
	}
	for i := range list {
		st := list[i]
		s.cache[st.ProfileID] = &st
	}
}

func (s *Scheduler) stateLocked(profileID string) *domain.ScheduleState {
	st, ok := s.cache[profileID]
	if !ok {
		st = &domain.ScheduleState{ProfileID: profileID}
		s.cache[profileID] = st
	}
	return st
}

func (s *Scheduler) persistLocked(ctx context.Context, st *domain.ScheduleState) {
	if s.states == nil {
		return
	}
	if err := s.states.SaveScheduleState(ctx, st); err != nil {
		s.opts.Logf("[WARN] scheduler: persist state for profile %s: %v", st.ProfileID, err)
	}
}

func (s *Scheduler) noticeOnce(profileID, key, format string, args ...any) {
	if s.noticed[profileID] == key {
		return
	}
	s.noticed[profileID] = key
	s.opts.Logf(format, args...)
}

func (s *Scheduler) publish(ev domain.LiveEvent) {
	if s.opts.Publish != nil {
		s.opts.Publish(ev)
	}
}

// IsActiveStatus reports statuses that block a new run of the same profile.
func IsActiveStatus(status string) bool {
	switch status {
	case domain.ScanStatusQueued, domain.ScanStatusCalibrating, domain.ScanStatusRunning,
		domain.ScanStatusPausedWindow, domain.ScanStatusPausedUser:
		return true
	}
	return false
}

func activeRunOf(runs []domain.ScanRun, profileID string) *domain.ScanRun {
	for i := range runs {
		if runs[i].ProfileID == profileID && IsActiveStatus(runs[i].Status) {
			return &runs[i]
		}
	}
	return nil
}

func lastRunOf(runs []domain.ScanRun, profileID string, scheduledOnly bool) *domain.ScanRun {
	var best *domain.ScanRun
	for i := range runs {
		r := &runs[i]
		if r.ProfileID != profileID || (scheduledOnly && r.TriggeredBy != TriggeredByScheduler) {
			continue
		}
		if best == nil || r.StartedAt.After(best.StartedAt) {
			best = r
		}
	}
	return best
}

func fmtTime(t time.Time, loc *time.Location) string {
	return t.In(loc).Format("2006-01-02 15:04 MST")
}
