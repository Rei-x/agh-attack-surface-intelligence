package db

import (
	"context"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// The per-profile "Capture screenshots" switch lives in its own column
// (scan_profiles.capture_screenshots, default true), outside the main profile queries.

func (s *PostgresStore) saveProfileScreenshots(ctx context.Context, p *domain.ScanProfile) error {
	_, err := s.pool.Exec(ctx, `UPDATE scan_profiles SET capture_screenshots=$1 WHERE id=$2`, p.ScreenshotsEnabled(), p.ID)
	return err
}

func (s *PostgresStore) loadProfileScreenshots(ctx context.Context, ps []domain.ScanProfile) {
	if len(ps) == 0 {
		return
	}
	rows, err := s.pool.Query(ctx, `SELECT id, capture_screenshots FROM scan_profiles`)
	if err != nil {
		return
	}
	defer rows.Close()
	on := map[string]bool{}
	for rows.Next() {
		var id string
		var v bool
		if rows.Scan(&id, &v) == nil {
			on[id] = v
		}
	}
	for i := range ps {
		if v, ok := on[ps[i].ID]; ok && !v {
			off := false
			ps[i].CaptureScreenshots = &off
		}
	}
}
