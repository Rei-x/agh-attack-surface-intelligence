package scanner

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// WindowGuard enforces hard scan time windows (including overnight windows such as 22:00-06:00).
type WindowGuard struct {
	Enabled     bool
	StartMinute int // minutes since midnight [0..1439]
	EndMinute   int // minutes since midnight [0..1439]
	Location    *time.Location
	Timezone    string
}

// NewWindowGuard parses HH:MM window boundaries and IANA timezone (defaulting to Europe/Warsaw).
func NewWindowGuard(enabled bool, startHHMM, endHHMM, tz string) (*WindowGuard, error) {
	if strings.TrimSpace(tz) == "" {
		tz = "Europe/Warsaw"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		// Fallback to UTC if system tzdata is unavailable, but keep explicit error for clearly invalid names if enabled.
		if tz == "UTC" || tz == "Europe/Warsaw" {
			loc = time.UTC
		} else {
			return nil, fmt.Errorf("invalid timezone %q: %w", tz, err)
		}
	}

	if !enabled {
		return &WindowGuard{
			Enabled:  false,
			Location: loc,
			Timezone: tz,
		}, nil
	}

	startMin, err := parseHHMM(startHHMM)
	if err != nil {
		return nil, fmt.Errorf("invalid window_start %q: %w", startHHMM, err)
	}
	endMin, err := parseHHMM(endHHMM)
	if err != nil {
		return nil, fmt.Errorf("invalid window_end %q: %w", endHHMM, err)
	}
	if startMin == endMin {
		return nil, fmt.Errorf("window_start and window_end cannot be identical (%s)", startHHMM)
	}

	return &WindowGuard{
		Enabled:     true,
		StartMinute: startMin,
		EndMinute:   endMin,
		Location:    loc,
		Timezone:    tz,
	}, nil
}

func parseHHMM(s string) (int, error) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("expected HH:MM")
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("hours must be 00-23 and minutes 00-59")
	}
	return h*60 + m, nil
}

// IsOpen returns true when scanning is permitted at the given instant.
func (w *WindowGuard) IsOpen(now time.Time) bool {
	if w == nil || !w.Enabled {
		return true
	}
	local := now.In(w.location())
	curMin := local.Hour()*60 + local.Minute()

	if w.StartMinute < w.EndMinute {
		// Same-day window, e.g. 08:00-18:00: [Start, End)
		return curMin >= w.StartMinute && curMin < w.EndMinute
	}
	// Overnight window, e.g. 22:00-06:00: [22:00..24:00) U [00:00..06:00)
	return curMin >= w.StartMinute || curMin < w.EndMinute
}

// Remaining returns how much time remains before the currently open window closes.
// Returns 0 if the window is currently closed. Returns 24h if window enforcement is disabled.
func (w *WindowGuard) Remaining(now time.Time) time.Duration {
	if w == nil || !w.Enabled {
		return 24 * time.Hour
	}
	if !w.IsOpen(now) {
		return 0
	}
	loc := w.location()
	local := now.In(loc)
	endH := w.EndMinute / 60
	endM := w.EndMinute % 60

	endToday := time.Date(local.Year(), local.Month(), local.Day(), endH, endM, 0, 0, loc)
	if !endToday.After(local) {
		endToday = endToday.AddDate(0, 0, 1)
	}
	return endToday.Sub(local)
}

// NextOpen returns the next timestamp at which the scan window opens.
// If the window is already open, it returns now in the configured timezone.
func (w *WindowGuard) NextOpen(now time.Time) time.Time {
	if w == nil || !w.Enabled {
		return now
	}
	loc := w.location()
	local := now.In(loc)
	if w.IsOpen(now) {
		return local
	}

	startH := w.StartMinute / 60
	startM := w.StartMinute % 60
	openToday := time.Date(local.Year(), local.Month(), local.Day(), startH, startM, 0, 0, loc)
	if !openToday.After(local) {
		openToday = openToday.AddDate(0, 0, 1)
	}
	return openToday
}

// WindowDuration returns the length of a single open window period.
func (w *WindowGuard) WindowDuration() time.Duration {
	if w == nil || !w.Enabled {
		return 24 * time.Hour
	}
	mins := w.EndMinute - w.StartMinute
	if mins <= 0 {
		mins += 24 * 60
	}
	return time.Duration(mins) * time.Minute
}

// FitsInWindow reports whether an estimated scan duration (in seconds) fits inside
// the remaining open window (if currently open) or inside a single full window (if closed).
func (w *WindowGuard) FitsInWindow(now time.Time, estSec int64) bool {
	if w == nil || !w.Enabled {
		return true
	}
	if estSec <= 0 {
		return true
	}
	estDur := time.Duration(estSec) * time.Second
	if w.IsOpen(now) {
		return estDur <= w.Remaining(now)
	}
	return estDur <= w.WindowDuration()
}

// EstimatedWindows computes how many scan windows are required to complete estSec of work.
func (w *WindowGuard) EstimatedWindows(estSec int64) int {
	if estSec <= 0 {
		return 1
	}
	if w == nil || !w.Enabled {
		return 1
	}
	winSec := w.WindowDuration().Seconds()
	if winSec <= 0 {
		return 1
	}
	n := int(math.Ceil(float64(estSec) / winSec))
	if n < 1 {
		return 1
	}
	return n
}

func (w *WindowGuard) location() *time.Location {
	if w != nil && w.Location != nil {
		return w.Location
	}
	return time.UTC
}
