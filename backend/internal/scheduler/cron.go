package scheduler

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// cronParser accepts standard 5-field cron (minute hour dom month dow) plus the usual
// descriptors (@hourly, @daily, @weekly, @monthly, @yearly). Seconds fields and @every are
// rejected: scans are long-running and minute granularity is all the scheduler supports.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// ParseCron validates and parses a 5-field cron expression. The timezone is NOT part of the
// expression; it comes from the profile and is applied by evaluating the schedule in that
// location (so "0 22 * * *" means 22:00 Europe/Warsaw, DST-aware).
func ParseCron(expr string) (cron.Schedule, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty cron expression")
	}
	up := strings.ToUpper(expr)
	if strings.HasPrefix(up, "TZ=") || strings.HasPrefix(up, "CRON_TZ=") {
		return nil, fmt.Errorf("timezone prefixes are not supported; set the profile timezone instead")
	}
	if strings.HasPrefix(expr, "@every") {
		return nil, fmt.Errorf("@every is not supported; use a 5-field cron expression")
	}
	if !strings.HasPrefix(expr, "@") && len(strings.Fields(expr)) != 5 {
		return nil, fmt.Errorf("expected 5 fields (minute hour day-of-month month day-of-week), got %d", len(strings.Fields(expr)))
	}
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return nil, err
	}
	return sched, nil
}

// ValidateCron returns a user-facing error for an invalid schedule_cron value (empty is valid
// and means "no recurring schedule").
func ValidateCron(expr string) error {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	if _, err := ParseCron(expr); err != nil {
		return fmt.Errorf("invalid schedule_cron %q: %v (example: \"0 22 * * *\" = daily at 22:00 in the profile timezone)", expr, err)
	}
	return nil
}

func loadLocation(tz string) *time.Location {
	if strings.TrimSpace(tz) == "" {
		tz = "Europe/Warsaw"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.UTC
	}
	return loc
}
