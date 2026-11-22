package db

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// GetChangeRollup returns the summary of the host's change events removed by retention.
func (m *MemoryStore) GetChangeRollup(_ context.Context, hostID string) (*domain.ChangeRollup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.changeRollups[hostID]
	if !ok || r.Count == 0 {
		return nil, nil
	}
	cp := r
	cp.ByType = make(map[string]int, len(r.ByType))
	for k, v := range r.ByType {
		cp.ByType[k] = v
	}
	if r.BySeverity != nil {
		cp.BySeverity = make(map[string]int, len(r.BySeverity))
		for k, v := range r.BySeverity {
			cp.BySeverity[k] = v
		}
	}
	return &cp, nil
}

// Compact applies p to the in-memory history (see RetentionPolicy) and migrates scan
// snapshots of stores loaded from older files to the slim, compressed form. It holds the
// write lock for the pass; the encrypted file store persists the result like any write.
func (m *MemoryStore) Compact(_ context.Context, p RetentionPolicy) (CompactionReport, error) {
	start := time.Now()
	var rep CompactionReport
	m.mu.Lock()
	if !p.Enabled() && m.snapshotFormat == snapshotFormatSlim {
		m.mu.Unlock()
		return rep, nil
	}
	var cutoff time.Time
	if p.Days > 0 {
		cutoff = time.Now().UTC().Add(-time.Duration(p.Days) * 24 * time.Hour)
	}

	// Runs newest first: the run-scoped limits keep the newest N runs.
	runs := make([]*encScanRunRow, 0, len(m.scanRuns))
	for id := range m.scanRuns {
		r := m.scanRuns[id]
		runs = append(runs, &r)
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].StartedAt.After(runs[j].StartedAt) })

	m.compactSnapshotsLocked(p, runs, &rep)
	m.compactRunDetailLocked(p, runs, &rep)
	m.migrateLegacyLocked(&rep)
	m.compactObservationsLocked(p, cutoff, &rep)
	m.compactChangesLocked(p, runs, cutoff, &rep)

	if p.AuditEntries > 0 && len(m.auditLogs) > p.AuditEntries {
		rep.AuditLogs = len(m.auditLogs) - p.AuditEntries
		m.auditLogs = append([]domain.AuditLog(nil), m.auditLogs[rep.AuditLogs:]...)
	}
	if p.ExportEntries > 0 && len(m.ddExports) > p.ExportEntries {
		rep.Exports = len(m.ddExports) - p.ExportEntries
		m.ddExports = append([]domain.DefectDojoExport(nil), m.ddExports[rep.Exports:]...)
	}
	// Per-run telemetry documents (api/telemetry.go) of runs that were deleted.
	for key := range m.settings {
		if runID, ok := strings.CutPrefix(key, "run_telemetry:"); ok {
			if _, exists := m.scanRuns[runID]; !exists {
				delete(m.settings, key)
				rep.TelemetryDocs++
			}
		}
	}

	rep.Duration = time.Since(start)
	if rep.Empty() {
		m.mu.Unlock()
		return rep, nil
	}
	m.unlockDirty()
	return rep, nil
}

// compactSnapshotsLocked keeps the snapshots of the newest p.SnapshotRuns runs and of the
// newest two runs of every profile (so the scan diff's default pair, the latest run and the
// previous run of its profile, always works) and drops snapshots of deleted runs.
func (m *MemoryStore) compactSnapshotsLocked(p RetentionPolicy, runs []*encScanRunRow, rep *CompactionReport) {
	if p.SnapshotRuns <= 0 {
		return
	}
	keep := make(map[string]bool, p.SnapshotRuns)
	perProfile := map[string]int{}
	kept := 0
	for _, r := range runs {
		if _, ok := m.snapshots[r.ID]; !ok {
			continue
		}
		if kept < p.SnapshotRuns || perProfile[r.ProfileID] < 2 {
			keep[r.ID] = true
			kept++
			perProfile[r.ProfileID]++
		}
	}
	for id := range m.snapshots {
		if !keep[id] {
			delete(m.snapshots, id)
			rep.Snapshots++
		}
	}
}

// migrateLegacyLocked rewrites what files from earlier releases hold in the old form: full
// scan snapshots become slim and compressed, raw nmap XML gets compressed. It runs once per
// loaded legacy store (after the limits above, so only kept payloads are rewritten); a
// payload that cannot be read is left as it is.
func (m *MemoryStore) migrateLegacyLocked(rep *CompactionReport) {
	if m.snapshotFormat == snapshotFormatSlim {
		return
	}
	for id, enc := range m.snapshots {
		aad := "scan_snapshots:" + id + ":payload"
		raw, err := m.vault.DecryptBytes(enc, aad)
		if err != nil || isGzip(raw) {
			continue
		}
		var hosts []domain.Host
		if err := json.Unmarshal(raw, &hosts); err != nil {
			continue
		}
		slim, err := encryptLargeJSON(m.vault, SlimSnapshotHosts(hosts), aad)
		if err != nil {
			continue
		}
		m.snapshots[id] = slim
		rep.MigratedSnapshots++
	}
	for id, row := range m.scanRuns {
		if row.RawNmapXMLEnc == "" {
			continue
		}
		aad := "scan_runs:" + id + ":raw_nmap_xml"
		raw, err := m.vault.DecryptBytes(row.RawNmapXMLEnc, aad)
		if err != nil || isGzip(raw) {
			continue
		}
		if enc, err := encryptLarge(m.vault, raw, aad); err == nil {
			row.RawNmapXMLEnc = enc
			m.scanRuns[id] = row
		}
	}
	m.snapshotFormat = snapshotFormatSlim
}

// compactRunDetailLocked drops the raw nmap XML and the per-chunk target lists and command
// lines of finished runs beyond the newest N. Runs that are still running or paused keep
// everything: resuming a run reads its chunk targets, agents merge into its XML.
func (m *MemoryStore) compactRunDetailLocked(p RetentionPolicy, runs []*encScanRunRow, rep *CompactionReport) {
	withXML, withDetail := 0, 0
	for _, r := range runs {
		if r.RawNmapXMLEnc != "" {
			withXML++
			if p.RawXMLRuns > 0 && withXML > p.RawXMLRuns && isTerminalRun(r.Status) {
				row := m.scanRuns[r.ID]
				row.RawNmapXMLEnc, row.HasRawNmapXML = "", false
				m.scanRuns[r.ID] = row
				rep.RawNmapXML++
			}
		}
		chunks := m.scanChunks[r.ID]
		if !chunksHaveDetail(chunks) {
			continue
		}
		withDetail++
		if p.ChunkDetailRuns > 0 && withDetail > p.ChunkDetailRuns && isTerminalRun(r.Status) {
			slim := make([]domain.ScanChunk, len(chunks))
			for i, c := range chunks {
				c.Targets, c.NmapCommands = nil, nil
				slim[i] = c
			}
			m.scanChunks[r.ID] = slim
			rep.ChunkDetails++
		}
	}
}

func chunksHaveDetail(chunks []domain.ScanChunk) bool {
	for i := range chunks {
		if len(chunks[i].Targets) > 0 || len(chunks[i].NmapCommands) > 0 {
			return true
		}
	}
	return false
}

// compactObservationsLocked keeps the newest p.ObservationsPerService observations of each
// service, drops those older than the cutoff (always keeping the newest one) and slims the
// HTTP fingerprint of all but the newest fullEvidenceObservations.
func (m *MemoryStore) compactObservationsLocked(p RetentionPolicy, cutoff time.Time, rep *CompactionReport) {
	if !p.Enabled() {
		return
	}
	for svcID, list := range m.observations {
		n := len(list)
		drop := 0
		if p.ObservationsPerService > 0 && n > p.ObservationsPerService {
			drop = n - p.ObservationsPerService
		}
		if !cutoff.IsZero() {
			for drop < n-1 && list[drop].ObservedAt.Before(cutoff) {
				drop++
			}
		}
		if drop > 0 {
			list = append([]encObservationRow(nil), list[drop:]...) // release the dropped rows
			m.observations[svcID] = list
			rep.Observations += drop
		}
		for i := 0; i < len(list)-fullEvidenceObservations; i++ {
			o := &list[i]
			if o.Slim || o.HTTPEnc == "" {
				continue
			}
			if slim, ok := m.slimObservationHTTPLocked(o); ok {
				o.HTTPEnc, o.Slim = slim, true
				rep.SlimmedObservations++
			}
		}
	}
}

func (m *MemoryStore) slimObservationHTTPLocked(o *encObservationRow) (string, bool) {
	aad := "service_observations:" + o.ID + ":http"
	var fp domain.HTTPFingerprint
	if err := m.vault.DecryptJSON(o.HTTPEnc, aad, &fp); err != nil {
		return "", false
	}
	enc, err := m.vault.EncryptJSON(SlimHTTP(&fp), aad)
	if err != nil {
		return "", false
	}
	return enc, true
}

// protectedChangeRuns is how many of the newest runs keep all their change events whatever
// the per-host cap says: the DefectDojo push, the alert webhook, the digest and the scan
// diff read the events of the latest runs, and one scan can add many events to one host.
const protectedChangeRuns = 3

// compactChangesLocked keeps per host the newest p.ChangesPerHost change events that are
// not older than the cutoff and folds the rest into the host's summary. Events of the
// newest protectedChangeRuns runs and of unfinished runs are never removed.
func (m *MemoryStore) compactChangesLocked(p RetentionPolicy, runs []*encScanRunRow, cutoff time.Time, rep *CompactionReport) {
	if p.ChangesPerHost <= 0 && cutoff.IsZero() {
		return
	}
	protected := map[string]bool{}
	for i, r := range runs {
		if i < protectedChangeRuns || !isTerminalRun(r.Status) {
			protected[r.ID] = true
		}
	}
	type ref struct {
		id string
		at time.Time
	}
	byHost := map[string][]ref{}
	for id, c := range m.changes {
		byHost[c.HostID] = append(byHost[c.HostID], ref{id: id, at: c.CreatedAt})
	}
	for hostID, refs := range byHost {
		sort.Slice(refs, func(i, j int) bool { return refs[i].at.After(refs[j].at) })
		for i, r := range refs {
			if (p.ChangesPerHost <= 0 || i < p.ChangesPerHost) && (cutoff.IsZero() || !r.at.Before(cutoff)) {
				continue
			}
			if protected[m.changes[r.id].ScanRunID] {
				continue
			}
			c := m.changes[r.id]
			delete(m.changes, r.id)
			rep.ChangeEvents++
			if hostID == "" {
				continue
			}
			roll := m.changeRollups[hostID]
			roll.HostID = hostID
			foldChange(&roll, c.EventType, c.Severity, c.CreatedAt)
			m.changeRollups[hostID] = roll
		}
	}
}
