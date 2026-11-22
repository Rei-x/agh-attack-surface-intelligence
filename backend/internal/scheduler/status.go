package scheduler

import (
	"context"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// RunRef is a compact reference to a scan run for schedule status payloads.
type RunRef struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	TriggeredBy string     `json:"triggered_by"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}

// Status is the schedule view of one profile, exposed as `schedule` on profile endpoints.
type Status struct {
	// Scheduled is true when the profile is enabled and has a valid schedule_cron.
	Scheduled bool   `json:"scheduled"`
	Cron      string `json:"cron,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
	CronError string `json:"cron_error,omitempty"`
	// NextSlotAt is the next raw cron slot; NextRunAt is when the scheduler will actually
	// start it (deferred to window open when the slot falls outside the time window).
	NextSlotAt       *time.Time `json:"next_slot_at,omitempty"`
	NextRunAt        *time.Time `json:"next_run_at,omitempty"`
	DeferredByWindow bool       `json:"deferred_by_window"`
	// PendingCatchUp is set when a slot is already due (missed during downtime, or waiting
	// for the window); it fires once at NextRunAt.
	PendingCatchUp bool `json:"pending_catch_up"`
	// WillSkip is set when an active run exists: the next due slot is skipped unless it finishes.
	WillSkip       bool       `json:"will_skip"`
	LastFireAt     *time.Time `json:"last_fire_at,omitempty"`
	LastSkipAt     *time.Time `json:"last_skip_at,omitempty"`
	LastSkipReason string     `json:"last_skip_reason,omitempty"`
	LastRun        *RunRef    `json:"last_run,omitempty"`
	ActiveRun      *RunRef    `json:"active_run,omitempty"`
}

// Statuses computes schedule status for the given profiles (one ListScanRuns call).
func (s *Scheduler) Statuses(ctx context.Context, profiles []domain.ScanProfile) map[string]Status {
	s.mu.Lock()
	s.ensureLoadedLocked(ctx)
	states := make(map[string]domain.ScheduleState, len(s.cache))
	for id, st := range s.cache {
		states[id] = *st
	}
	s.mu.Unlock()

	runs, _ := s.store.ListScanRuns(ctx, 500)
	now := s.opts.Now()
	out := make(map[string]Status, len(profiles))
	for _, p := range profiles {
		var st *domain.ScheduleState
		if v, ok := states[p.ID]; ok {
			st = &v
		}
		out[p.ID] = ComputeStatus(p, st, runs, now)
	}
	return out
}

// ComputeStatus is the pure status function (state may be nil).
func ComputeStatus(p domain.ScanProfile, st *domain.ScheduleState, runs []domain.ScanRun, now time.Time) Status {
	expr := strings.TrimSpace(p.ScheduleCron)
	out := Status{Cron: expr, Timezone: p.Timezone}
	if last := lastRunOf(runs, p.ID, false); last != nil {
		out.LastRun = refOf(last)
	}
	if active := activeRunOf(runs, p.ID); active != nil {
		out.ActiveRun = refOf(active)
	}
	if st != nil {
		out.LastFireAt = st.LastFireAt
		out.LastSkipAt = st.LastSkipAt
		out.LastSkipReason = st.LastSkipReason
	}
	if expr == "" {
		return out
	}
	sched, err := ParseCron(expr)
	if err != nil {
		out.CronError = err.Error()
		return out
	}
	if !p.Enabled {
		return out
	}
	out.Scheduled = true
	loc := loadLocation(p.Timezone)
	anchor := now
	if st != nil && st.AnchorAt != nil && st.Cron == expr {
		anchor = *st.AnchorAt
	}
	slot := sched.Next(anchor.In(loc))
	if slot.IsZero() {
		return out
	}
	wg, werr := scanner.NewWindowGuard(p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone)
	next := slot
	if !slot.After(now) {
		out.PendingCatchUp = true
		next = now
	}
	if werr == nil && !wg.IsOpen(next) {
		next = wg.NextOpen(next)
		out.DeferredByWindow = true
	}
	slotUTC, nextUTC := slot.UTC(), next.UTC()
	out.NextSlotAt = &slotUTC
	out.NextRunAt = &nextUTC
	out.WillSkip = out.ActiveRun != nil
	return out
}

func refOf(r *domain.ScanRun) *RunRef {
	return &RunRef{ID: r.ID, Name: r.Name, Status: r.Status, TriggeredBy: r.TriggeredBy, StartedAt: r.StartedAt, FinishedAt: r.FinishedAt}
}
