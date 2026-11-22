package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/jackc/pgx/v5"
)

// PostgreSQL applies the same RetentionPolicy as the in-memory store with set-based SQL
// deletes, in one transaction. It keeps the history in tables, not in the process heap, so
// retention there bounds disk use and query cost rather than RSS. Differences from the
// memory store: older observations keep their full HTTP fingerprint (the column is a per-row
// ciphertext that only Go can rewrite, and rewriting saves disk only) and legacy snapshots
// are not re-slimmed (new ones are slim and compressed, old ones age out by the limit).

var (
	_ Compactor         = (*PostgresStore)(nil)
	_ ChangeRollupStore = (*PostgresStore)(nil)
)

const terminalRunStatuses = `('` + domain.ScanStatusCompleted + `','` + domain.ScanStatusFailed + `','` + domain.ScanStatusStopped + `')`

// Compact applies p with SQL (see RetentionPolicy for the semantics of every limit).
func (s *PostgresStore) Compact(ctx context.Context, p RetentionPolicy) (CompactionReport, error) {
	start := time.Now()
	var rep CompactionReport
	if !p.Enabled() {
		return rep, nil
	}
	var cutoff *time.Time
	if p.Days > 0 {
		c := time.Now().UTC().Add(-time.Duration(p.Days) * 24 * time.Hour)
		cutoff = &c
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return rep, err
	}
	defer tx.Rollback(ctx)

	exec := func(dst *int, sql string, args ...any) error {
		if err != nil {
			return err
		}
		tag, e := tx.Exec(ctx, sql, args...)
		if e != nil {
			err = e
			return err
		}
		if dst != nil {
			*dst += int(tag.RowsAffected())
		}
		return nil
	}

	if p.ObservationsPerService > 0 || cutoff != nil {
		_ = exec(&rep.Observations, `
			DELETE FROM service_observations WHERE id IN (
				SELECT id FROM (
					SELECT id, observed_at,
					       row_number() OVER (PARTITION BY service_id ORDER BY observed_at DESC, id DESC) AS rn
					FROM service_observations
				) x
				WHERE x.rn > 1 AND (($1 > 0 AND x.rn > $1) OR ($2::timestamptz IS NOT NULL AND x.observed_at < $2))
			)`, p.ObservationsPerService, cutoff)
	}
	if err == nil && (p.ChangesPerHost > 0 || cutoff != nil) {
		err = s.compactChangesTx(ctx, tx, p, cutoff, &rep)
	}
	if p.SnapshotRuns > 0 {
		_ = exec(&rep.Snapshots, `
			DELETE FROM scan_snapshots WHERE scan_run_id IN (
				SELECT scan_run_id FROM (
					SELECT sn.scan_run_id,
					       row_number() OVER (ORDER BY r.started_at DESC) AS rn,
					       row_number() OVER (PARTITION BY r.profile_id ORDER BY r.started_at DESC) AS prn
					FROM scan_snapshots sn JOIN scan_runs r ON r.id = sn.scan_run_id
				) x WHERE x.rn > $1 AND x.prn > 2
			)`, p.SnapshotRuns)
	}
	if p.RawXMLRuns > 0 {
		_ = exec(&rep.RawNmapXML, `
			UPDATE scan_runs r SET raw_nmap_xml_enc = '', has_raw_nmap_xml = FALSE
			FROM (
				SELECT id, status, row_number() OVER (ORDER BY started_at DESC) AS rn
				FROM scan_runs WHERE raw_nmap_xml_enc <> ''
			) x
			WHERE r.id = x.id AND x.rn > $1 AND x.status IN `+terminalRunStatuses, p.RawXMLRuns)
	}
	if p.ChunkDetailRuns > 0 {
		_ = exec(&rep.ChunkDetails, `
			WITH detailed AS (
				SELECT r.id, r.status, row_number() OVER (ORDER BY r.started_at DESC) AS rn
				FROM scan_runs r
				WHERE EXISTS (SELECT 1 FROM scan_chunks c WHERE c.scan_run_id = r.id
				              AND (c.targets <> '[]'::jsonb OR c.nmap_commands <> '[]'::jsonb))
			), doomed AS (
				SELECT id FROM detailed WHERE rn > $1 AND status IN `+terminalRunStatuses+`
			), upd AS (
				UPDATE scan_chunks c SET targets = '[]'::jsonb, nmap_commands = '[]'::jsonb
				FROM doomed d WHERE c.scan_run_id = d.id
				RETURNING c.scan_run_id
			)
			SELECT 1 FROM doomed`, p.ChunkDetailRuns)
	}
	if p.AuditEntries > 0 {
		_ = exec(&rep.AuditLogs, `
			DELETE FROM audit_logs WHERE id IN (
				SELECT id FROM audit_logs ORDER BY created_at DESC, id DESC OFFSET $1
			)`, p.AuditEntries)
	}
	if p.ExportEntries > 0 {
		_ = exec(&rep.Exports, `
			DELETE FROM defectdojo_exports WHERE id IN (
				SELECT id FROM defectdojo_exports ORDER BY created_at DESC, id DESC OFFSET $1
			)`, p.ExportEntries)
	}
	_ = exec(&rep.TelemetryDocs, `
		DELETE FROM app_settings
		WHERE key LIKE 'run_telemetry:%' AND substr(key, 15) NOT IN (SELECT id FROM scan_runs)`)
	if err != nil {
		return rep, fmt.Errorf("retention: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return rep, err
	}
	rep.Duration = time.Since(start)
	return rep, nil
}

// compactChangesTx deletes change events beyond the per-host cap or older than the cutoff
// (never those of the newest protectedChangeRuns runs or of unfinished runs) and merges the
// removed events into change_rollups.
func (s *PostgresStore) compactChangesTx(ctx context.Context, tx pgx.Tx, p RetentionPolicy, cutoff *time.Time, rep *CompactionReport) error {
	rows, err := tx.Query(ctx, `
		WITH protected AS (
			(SELECT id FROM scan_runs ORDER BY started_at DESC LIMIT $3)
			UNION
			SELECT id FROM scan_runs WHERE status NOT IN `+terminalRunStatuses+`
		), doomed AS (
			SELECT id FROM (
				SELECT id, scan_run_id, created_at,
				       row_number() OVER (PARTITION BY host_id ORDER BY created_at DESC, id DESC) AS rn
				FROM change_events
			) x
			WHERE (($1 > 0 AND x.rn > $1) OR ($2::timestamptz IS NOT NULL AND x.created_at < $2))
			  AND x.scan_run_id NOT IN (SELECT id FROM protected)
		), deleted AS (
			DELETE FROM change_events c USING doomed d WHERE c.id = d.id
			RETURNING c.host_id, c.event_type, c.severity, c.created_at
		)
		SELECT host_id, event_type, severity, count(*), min(created_at), max(created_at)
		FROM deleted GROUP BY host_id, event_type, severity`, p.ChangesPerHost, cutoff, protectedChangeRuns)
	if err != nil {
		return err
	}
	rolls := map[string]*domain.ChangeRollup{}
	for rows.Next() {
		var hostID, eventType, severity string
		var n int
		var from, to time.Time
		if err := rows.Scan(&hostID, &eventType, &severity, &n, &from, &to); err != nil {
			rows.Close()
			return err
		}
		rep.ChangeEvents += n
		if hostID == "" {
			continue
		}
		r := rolls[hostID]
		if r == nil {
			r = &domain.ChangeRollup{HostID: hostID}
			rolls[hostID] = r
		}
		mergeRollup(r, domain.ChangeRollup{Count: n, ByType: map[string]int{eventType: n},
			BySeverity: map[string]int{severity: n}, From: from, To: to})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for hostID, add := range rolls {
		cur, err := getChangeRollup(ctx, tx, hostID)
		if err != nil {
			return err
		}
		if cur == nil {
			cur = &domain.ChangeRollup{HostID: hostID}
		}
		mergeRollup(cur, *add)
		byType, _ := json.Marshal(cur.ByType)
		bySev, _ := json.Marshal(cur.BySeverity)
		if _, err := tx.Exec(ctx, `
			INSERT INTO change_rollups (host_id, count, by_type, by_severity, first_at, last_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (host_id) DO UPDATE SET count=EXCLUDED.count, by_type=EXCLUDED.by_type,
			       by_severity=EXCLUDED.by_severity, first_at=EXCLUDED.first_at, last_at=EXCLUDED.last_at`,
			hostID, cur.Count, string(byType), string(bySev), cur.From, cur.To); err != nil {
			return err
		}
	}
	return nil
}

// mergeRollup adds b's counts and time range to a.
func mergeRollup(a *domain.ChangeRollup, b domain.ChangeRollup) {
	a.Count += b.Count
	if a.ByType == nil {
		a.ByType = map[string]int{}
	}
	for k, v := range b.ByType {
		a.ByType[k] += v
	}
	for k, v := range b.BySeverity {
		if k == "" {
			continue
		}
		if a.BySeverity == nil {
			a.BySeverity = map[string]int{}
		}
		a.BySeverity[k] += v
	}
	if !b.From.IsZero() && (a.From.IsZero() || b.From.Before(a.From)) {
		a.From = b.From
	}
	if b.To.After(a.To) {
		a.To = b.To
	}
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getChangeRollup(ctx context.Context, q queryRower, hostID string) (*domain.ChangeRollup, error) {
	var r domain.ChangeRollup
	var byType, bySev []byte
	var from, to *time.Time
	err := q.QueryRow(ctx, `SELECT host_id, count, by_type, by_severity, first_at, last_at FROM change_rollups WHERE host_id=$1`, hostID).
		Scan(&r.HostID, &r.Count, &byType, &bySev, &from, &to)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(byType, &r.ByType)
	_ = json.Unmarshal(bySev, &r.BySeverity)
	if from != nil {
		r.From = *from
	}
	if to != nil {
		r.To = *to
	}
	return &r, nil
}

// GetChangeRollup returns the summary of the host's change events removed by retention.
func (s *PostgresStore) GetChangeRollup(ctx context.Context, hostID string) (*domain.ChangeRollup, error) {
	r, err := getChangeRollup(ctx, s.pool, hostID)
	if err != nil || r == nil || r.Count == 0 {
		return nil, err
	}
	return r, nil
}
