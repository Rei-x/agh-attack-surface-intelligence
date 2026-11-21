package api

import (
	"fmt"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// Input validation shared by targets, exclusions, ad-hoc scans and profiles: bad input is
// rejected with a 400 and a Polish/English message instead of failing later in the scan.

const (
	maxTargetEntries = 100000 // entries per profile / scan request
	maxNameLen       = 200
	maxNotesLen      = 10000
)

// splitTargetList accepts entries separated by newlines, commas or semicolons (pasted from a
// spreadsheet or a text file) and drops blanks.
func splitTargetList(values []string) []string {
	var out []string
	for _, v := range values {
		for _, f := range strings.FieldsFunc(v, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ';'
		}) {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}

// validateTargetList checks every entry and the overall size; it returns the cleaned list.
func validateTargetList(values []string) ([]string, error) {
	entries := splitTargetList(values)
	if len(entries) > maxTargetEntries {
		return nil, fmt.Errorf("za dużo celów (%d, limit %d) / too many target entries", len(entries), maxTargetEntries)
	}
	var bad []string
	for _, e := range entries {
		if _, err := scanner.ValidateTargetEntry(e, scanner.DefaultMaxExpandedIPs); err != nil {
			bad = append(bad, err.Error())
			if len(bad) >= 5 {
				break
			}
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("niepoprawne cele / invalid targets: %s", strings.Join(bad, "; "))
	}
	return entries, nil
}

func validatePortSpec(spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	if _, err := scanner.ParsePorts(spec); err != nil {
		return fmt.Errorf("niepoprawna lista portów (dozwolone 1-65535, np. 22,80,443,8000-8100) / invalid ports: %v", err)
	}
	return nil
}

type intRange struct {
	name     string
	val      int
	min, max int
}

func checkRanges(rs ...intRange) error {
	for _, r := range rs {
		if r.val != 0 && (r.val < r.min || r.val > r.max) {
			return fmt.Errorf("%s musi być w zakresie %d-%d (podano %d) / %s must be between %d and %d",
				r.name, r.min, r.max, r.val, r.name, r.min, r.max)
		}
	}
	return nil
}

// validateScanParams validates the user-controlled knobs of a profile or ad-hoc scan.
func validateScanParams(p *domain.ScanProfile) error {
	if len(p.Name) > maxNameLen {
		return fmt.Errorf("nazwa za długa (max %d znaków) / name too long", maxNameLen)
	}
	targets, err := validateTargetList(p.Targets)
	if err != nil {
		return err
	}
	p.Targets = targets
	if err := validatePortSpec(p.AllowedPorts); err != nil {
		return err
	}
	return checkRanges(
		intRange{"max_rate_pps", p.MaxRatePPS, 1, 1000000},
		intRange{"http_rps", p.HTTPRPS, 1, 10000},
		intRange{"concurrency", p.Concurrency, 1, 4096},
		intRange{"chunk_target_sec", p.ChunkTargetSec, 5, 86400},
		intRange{"missing_threshold", p.MissingThreshold, 1, 1000},
		intRange{"grace_period_hours", p.GracePeriodHours, 1, 24 * 365},
	)
}
