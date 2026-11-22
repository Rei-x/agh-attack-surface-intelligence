// Package locale holds the instance's language and timezone rules for human-facing text:
// owner notices, ticket history notes and the morning digest. Every date shown to a
// person goes through here, in one format (ISO 2006-01-02), in the instance timezone
// (Europe/Warsaw unless configured otherwise), so a service first seen at 00:39 Warsaw time
// on 22 November is "2026-11-22" everywhere, never the UTC day before.
package locale

import (
	"fmt"
	"strings"
	"time"
	// The zone database is embedded so Europe/Warsaw resolves on hosts without one
	// (Windows, scratch images); a silent fallback to UTC is the bug this package exists
	// to prevent.
	_ "time/tzdata"
)

// Notice languages.
const (
	PL = "pl"
	EN = "en"
)

// Languages lists the supported notice languages, default first.
var Languages = []string{PL, EN}

// DefaultTimezone is the instance timezone when none is configured.
const DefaultTimezone = "Europe/Warsaw"

// Layouts used in every human-facing text.
const (
	DateLayout     = "2006-01-02"
	DateTimeLayout = "2006-01-02 15:04"
)

// Lang normalises a language code ("PL", " en ") and returns "" for unsupported ones.
func Lang(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case PL:
		return PL
	case EN:
		return EN
	}
	return ""
}

// ValidTimezone reports whether name is a loadable IANA zone.
func ValidTimezone(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if _, err := time.LoadLocation(strings.TrimSpace(name)); err != nil {
		return fmt.Errorf("unknown timezone %q", name)
	}
	return nil
}

// Location loads the zone name; empty or unknown names give DefaultTimezone.
func Location(name string) *time.Location {
	if name = strings.TrimSpace(name); name != "" {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc
		}
	}
	loc, err := time.LoadLocation(DefaultTimezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

// Date is the calendar day of t in loc ("2026-11-22").
func Date(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	return t.In(loc).Format(DateLayout)
}

// DateTime is t in loc as "2026-11-22 00:39 CET".
func DateTime(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return ""
	}
	return t.In(loc).Format(DateTimeLayout + " MST")
}

// EndOfDay is 23:59 of the ISO day in loc: due dates are "by the end of that day" where
// the owner is.
func EndOfDay(day string, loc *time.Location) (time.Time, error) {
	d, err := time.ParseInLocation(DateLayout, strings.TrimSpace(day), loc)
	if err != nil {
		return time.Time{}, fmt.Errorf("date must be YYYY-MM-DD: %q", day)
	}
	return time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 0, 0, loc), nil
}

// AddDays adds n calendar days to an ISO day ("2026-11-21" + 90 = "2027-02-19").
func AddDays(day string, n int) (string, error) {
	d, err := time.Parse(DateLayout, strings.TrimSpace(day))
	if err != nil {
		return "", fmt.Errorf("date must be YYYY-MM-DD: %q", day)
	}
	return d.AddDate(0, 0, n).Format(DateLayout), nil
}

// DueDay is the calendar day a due time stands for. Tickets of older versions stored the
// due date as 23:59 UTC of the day; read in Warsaw that is 00:59 of the next day, so a
// 23:59 UTC value keeps its UTC day. New due times are 23:59 in the instance zone, which
// is never 23:59 UTC unless the zone is UTC itself (same day either way).
func DueDay(due time.Time, loc *time.Location) string {
	if due.IsZero() {
		return ""
	}
	if u := due.UTC(); u.Hour() == 23 && u.Minute() == 59 {
		return u.Format(DateLayout)
	}
	return due.In(loc).Format(DateLayout)
}
