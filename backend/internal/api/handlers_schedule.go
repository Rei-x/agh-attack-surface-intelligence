package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scheduler"
)

// profileWithSchedule is a ScanProfile plus its recurring-schedule status. The profile fields
// stay flattened at the top level, so existing clients keep working; `schedule` is additive.
type profileWithSchedule struct {
	domain.ScanProfile
	Schedule scheduler.Status `json:"schedule"`
}

// scheduler returns the process-wide scheduler started in cmd/server, or (tests / embedded
// use without Start) a non-ticking scheduler bound to this server's store and runner, which
// still provides status and run-now with the same no-concurrent-run guarantee.
func (s *Server) scheduler() *scheduler.Scheduler {
	if d := scheduler.Default(); d != nil {
		return d
	}
	s.schedOnce.Do(func() {
		s.localSched = scheduler.New(s.store, s.runner, scheduler.Options{Publish: s.hub.Publish})
	})
	return s.localSched
}

func (s *Server) withSchedules(r *http.Request, profiles []domain.ScanProfile) []profileWithSchedule {
	statuses := s.scheduler().Statuses(r.Context(), profiles)
	out := make([]profileWithSchedule, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, profileWithSchedule{ScanProfile: p, Schedule: statuses[p.ID]})
	}
	return out
}

// validateProfileSchedule checks schedule_cron, timezone and window before persisting.
func validateProfileSchedule(p *domain.ScanProfile) error {
	p.ScheduleCron = strings.TrimSpace(p.ScheduleCron)
	if err := scheduler.ValidateCron(p.ScheduleCron); err != nil {
		return err
	}
	if p.WindowEnabled || p.ScheduleCron != "" {
		if _, err := scanner.NewWindowGuard(p.WindowEnabled, p.WindowStart, p.WindowEnd, p.Timezone); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.withSchedules(r, []domain.ScanProfile{*p})[0])
}

// handleRunProfileNow starts a profile immediately ("run now"). 409 if it already has an
// active run (QUEUED/RUNNING/PAUSED_*): a profile never runs twice concurrently.
func (s *Server) handleRunProfileNow(w http.ResponseWriter, r *http.Request) {
	run, err := s.scheduler().RunNow(r.Context(), r.PathValue("id"), currentUsername(r))
	if err != nil {
		var busy *scheduler.BusyError
		if errors.As(err, &busy) {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":      err.Error(),
				"active_run": busy.Run,
			})
			return
		}
		if strings.Contains(err.Error(), "no targets") {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}
