package db

import (
	"context"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// ScheduleStateStore is an optional extension implemented by MemoryStore and PostgresStore
// that persists recurring-scan scheduler bookkeeping across restarts. It is intentionally not
// part of Store so other Store implementations keep compiling; the scheduler type-asserts it.
type ScheduleStateStore interface {
	ListScheduleStates(ctx context.Context) ([]domain.ScheduleState, error)
	SaveScheduleState(ctx context.Context, st *domain.ScheduleState) error
}

var (
	_ ScheduleStateStore = (*MemoryStore)(nil)
	_ ScheduleStateStore = (*PostgresStore)(nil)
)

func (m *MemoryStore) ListScheduleStates(_ context.Context) ([]domain.ScheduleState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]domain.ScheduleState, 0, len(m.scheduleStates))
	for _, st := range m.scheduleStates {
		out = append(out, st)
	}
	return out, nil
}

func (m *MemoryStore) SaveScheduleState(_ context.Context, st *domain.ScheduleState) error {
	m.mu.Lock()
	defer m.unlockDirty() // persisted by the encrypted file store snapshot
	if m.scheduleStates == nil {
		m.scheduleStates = make(map[string]domain.ScheduleState)
	}
	st.UpdatedAt = time.Now().UTC()
	m.scheduleStates[st.ProfileID] = *st
	return nil
}

func (s *PostgresStore) ListScheduleStates(ctx context.Context) ([]domain.ScheduleState, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT profile_id, cron, anchor_at, last_fire_at, last_run_id, last_skip_at, last_skip_reason, updated_at
		FROM scan_schedule_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.ScheduleState{}
	for rows.Next() {
		var st domain.ScheduleState
		if err := rows.Scan(&st.ProfileID, &st.Cron, &st.AnchorAt, &st.LastFireAt, &st.LastRunID, &st.LastSkipAt, &st.LastSkipReason, &st.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SaveScheduleState(ctx context.Context, st *domain.ScheduleState) error {
	st.UpdatedAt = time.Now().UTC()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO scan_schedule_state (profile_id, cron, anchor_at, last_fire_at, last_run_id, last_skip_at, last_skip_reason, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (profile_id) DO UPDATE SET cron=EXCLUDED.cron, anchor_at=EXCLUDED.anchor_at, last_fire_at=EXCLUDED.last_fire_at,
		       last_run_id=EXCLUDED.last_run_id, last_skip_at=EXCLUDED.last_skip_at, last_skip_reason=EXCLUDED.last_skip_reason,
		       updated_at=EXCLUDED.updated_at`,
		st.ProfileID, st.Cron, st.AnchorAt, st.LastFireAt, st.LastRunID, st.LastSkipAt, st.LastSkipReason, st.UpdatedAt)
	return err
}
