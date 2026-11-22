package locale

import (
	"testing"
	"time"
)

func TestDatesAroundMidnightUseTheInstanceZone(t *testing.T) {
	warsaw := Location("Europe/Warsaw")
	if warsaw.String() != "Europe/Warsaw" {
		t.Fatalf("zone database not available: %s", warsaw)
	}
	// 00:39 in Warsaw on 22 November is still 21 November in UTC.
	seen := time.Date(2026, 11, 21, 23, 39, 0, 0, time.UTC)
	if got := Date(seen, warsaw); got != "2026-11-22" {
		t.Fatalf("first seen in Warsaw: %s", got)
	}
	if got := Date(seen, time.UTC); got != "2026-11-21" {
		t.Fatalf("UTC day: %s", got)
	}
	if got := DateTime(seen, warsaw); got != "2026-11-22 00:39 CET" {
		t.Fatalf("date time: %s", got)
	}
	// Summer time: 23:30 UTC on 30 June is 01:30 on 1 July in Warsaw.
	if got := DateTime(time.Date(2026, 6, 30, 23, 30, 0, 0, time.UTC), warsaw); got != "2026-07-01 01:30 CEST" {
		t.Fatalf("summer: %s", got)
	}
	// The last minute of the day in Warsaw stays on that day.
	if got := Date(time.Date(2026, 11, 22, 22, 59, 0, 0, time.UTC), warsaw); got != "2026-11-22" {
		t.Fatalf("23:59 Warsaw: %s", got)
	}
	if got := Date(time.Date(2026, 11, 22, 23, 0, 0, 0, time.UTC), warsaw); got != "2026-11-23" {
		t.Fatalf("00:00 Warsaw: %s", got)
	}
}

func TestEndOfDayAndDueDay(t *testing.T) {
	warsaw := Location("")
	if warsaw.String() != DefaultTimezone {
		t.Fatalf("default zone: %s", warsaw)
	}
	due, err := EndOfDay("2026-12-22", warsaw)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 12, 22, 22, 59, 0, 0, time.UTC); !due.Equal(want) {
		t.Fatalf("end of day: %s, want %s", due.UTC(), want)
	}
	if got := DueDay(due, warsaw); got != "2026-12-22" {
		t.Fatalf("due day: %s", got)
	}
	// Older tickets: 23:59 UTC of the day. In Warsaw that is already the next day, but the
	// ticket keeps its date.
	legacy := time.Date(2026, 12, 22, 23, 59, 0, 0, time.UTC)
	if got := DueDay(legacy, warsaw); got != "2026-12-22" {
		t.Fatalf("legacy due day: %s", got)
	}
	// West of UTC the end of the local day is the next UTC day.
	ny := Location("America/New_York")
	nyDue, _ := EndOfDay("2026-12-22", ny)
	if nyDue.UTC().Day() != 23 || DueDay(nyDue, ny) != "2026-12-22" {
		t.Fatalf("New York due: %s / %s", nyDue.UTC(), DueDay(nyDue, ny))
	}
	if _, err := EndOfDay("12/22/2026", warsaw); err == nil {
		t.Fatal("US dates must be refused")
	}
	if got, _ := AddDays("2026-11-21", 90); got != "2027-02-19" {
		t.Fatalf("add days: %s", got)
	}
}

func TestLangAndZones(t *testing.T) {
	if Lang(" PL ") != PL || Lang("en") != EN || Lang("de") != "" {
		t.Fatal("lang normalisation")
	}
	if ValidTimezone("Europe/Warsaw") != nil || ValidTimezone("") != nil || ValidTimezone("Mars/Base") == nil {
		t.Fatal("timezone validation")
	}
	if Location("Mars/Base").String() != DefaultTimezone {
		t.Fatal("unknown zones fall back to the default")
	}
}
