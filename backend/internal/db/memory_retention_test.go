package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func newRetentionStore(t *testing.T) (*MemoryStore, *crypto.Vault) {
	t.Helper()
	vault, err := crypto.NewVault(testMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	return NewMemoryStore(vault), vault
}

func fullFP(title string) *domain.HTTPFingerprint {
	return &domain.HTTPFingerprint{
		URL: "http://10.0.0.1/", Scheme: "http", StatusCode: 200, Title: title, ServerHeader: "nginx",
		Headers:     map[string]string{"Server": "nginx", "X-Powered-By": "PHP/8.1"},
		BodySnippet: "<html>secret body</html>",
		Cookies:     []domain.CookieInfo{{Name: "PHPSESSID"}},
	}
}

func TestCompactObservations(t *testing.T) {
	ctx := context.Background()
	m, _ := newRetentionStore(t)
	now := time.Now().UTC()
	h, _ := m.UpsertObservedHost(ctx, &domain.Host{IP: "10.0.0.1", FirstSeen: now, LastSeen: now})
	svc, _ := m.UpsertObservedService(ctx, &domain.Service{HostID: h.ID, Port: 80, State: "open", FirstSeen: now, LastSeen: now})
	// 40 daily observations, oldest first (the order AddObservation appends in).
	for i := 39; i >= 0; i-- {
		if err := m.AddObservation(ctx, &ServiceObservation{ScanRunID: fmt.Sprintf("run-%d", i), HostID: h.ID, ServiceID: svc.ID,
			Port: 80, State: "open", Banner: "b", HTTP: fullFP(fmt.Sprintf("day %d", i)), ObservedAt: now.Add(-time.Duration(i) * 24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := m.Compact(ctx, RetentionPolicy{ObservationsPerService: 25, Days: 10})
	if err != nil {
		t.Fatal(err)
	}
	obs, _ := m.ListServiceObservations(ctx, svc.ID, 0) // newest first
	if len(obs) != 10 || rep.Observations != 30 {
		t.Fatalf("kept %d observations (removed %d), want days 0..9", len(obs), rep.Observations)
	}
	if obs[0].HTTP.Title != "day 0" || obs[len(obs)-1].HTTP.Title != "day 9" {
		t.Fatalf("wrong observations kept: newest %q oldest %q", obs[0].HTTP.Title, obs[len(obs)-1].HTTP.Title)
	}
	for i, o := range obs {
		full := o.HTTP.Headers != nil && o.HTTP.BodySnippet != ""
		if i < fullEvidenceObservations && !full {
			t.Fatalf("observation %d (newest) lost its full fingerprint", i)
		}
		if i >= fullEvidenceObservations && (full || len(o.HTTP.Cookies) > 0 || o.HTTP.Title == "" || o.HTTP.StatusCode != 200) {
			t.Fatalf("observation %d should be slim but keep title/status: %+v", i, o.HTTP)
		}
	}
	if rep.SlimmedObservations != 10-fullEvidenceObservations {
		t.Fatalf("slimmed %d", rep.SlimmedObservations)
	}
	// A second pass has nothing left to do.
	if rep2, _ := m.Compact(ctx, RetentionPolicy{ObservationsPerService: 25, Days: 10}); !rep2.Empty() {
		t.Fatalf("second pass not empty: %s", rep2)
	}
	// Everything older than the cutoff: the newest observation stays as evidence.
	rep, _ = m.Compact(ctx, RetentionPolicy{Days: 1, ObservationsPerService: 25})
	obs, _ = m.ListServiceObservations(ctx, svc.ID, 0)
	if len(obs) != 1 || obs[0].HTTP.Title != "day 0" {
		t.Fatalf("expected only the newest observation, got %d (%s)", len(obs), rep)
	}
}

func TestCompactChangesFoldsIntoRollup(t *testing.T) {
	ctx := context.Background()
	m, _ := newRetentionStore(t)
	now := time.Now().UTC()
	for i := 0; i < 50; i++ {
		typ := "HOST_MISSING"
		if i%2 == 1 {
			typ = "HOST_REACTIVATED"
		}
		_ = m.AddChangeEvent(ctx, &domain.ChangeEvent{HostID: "h1", HostIP: "10.0.0.1", EventType: typ, Severity: "low",
			Summary: "flap", CreatedAt: now.Add(-time.Duration(i) * time.Hour)})
	}
	_ = m.AddChangeEvent(ctx, &domain.ChangeEvent{HostID: "h2", HostIP: "10.0.0.2", EventType: "NEW_HOST", Severity: "medium",
		CreatedAt: now.Add(-200 * 24 * time.Hour)})
	_ = m.AddChangeEvent(ctx, &domain.ChangeEvent{HostID: "h3", EventType: "NEW_HOST", CreatedAt: now})

	rep, err := m.Compact(ctx, RetentionPolicy{ChangesPerHost: 20, Days: 90})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChangeEvents != 31 {
		t.Fatalf("removed %d change events, want 30 (h1 cap) + 1 (h2 age)", rep.ChangeEvents)
	}
	kept, _ := m.ListChangeEvents(ctx, ChangeFilter{HostID: "h1"})
	if len(kept) != 20 || !kept[0].CreatedAt.Equal(now) {
		t.Fatalf("h1 kept %d events", len(kept))
	}
	roll, _ := m.GetChangeRollup(ctx, "h1")
	if roll == nil || roll.Count != 30 || roll.ByType["HOST_MISSING"] != 15 || roll.ByType["HOST_REACTIVATED"] != 15 || roll.BySeverity["low"] != 30 {
		t.Fatalf("rollup: %+v", roll)
	}
	if !roll.To.Equal(now.Add(-20*time.Hour)) || !roll.From.Equal(now.Add(-49*time.Hour)) {
		t.Fatalf("rollup range %v .. %v", roll.From, roll.To)
	}
	if r2, _ := m.GetChangeRollup(ctx, "h2"); r2 == nil || r2.Count != 1 || r2.ByType["NEW_HOST"] != 1 {
		t.Fatalf("h2 rollup: %+v", r2)
	}
	if r3, _ := m.GetChangeRollup(ctx, "h3"); r3 != nil {
		t.Fatalf("h3 lost nothing, rollup %+v", r3)
	}
	// One scan adding many events to a host: the newest runs keep all of theirs.
	run := &domain.ScanRun{ID: NewID(), Status: domain.ScanStatusCompleted, StartedAt: now}
	_ = m.CreateScanRun(ctx, run)
	for i := 0; i < 30; i++ {
		_ = m.AddChangeEvent(ctx, &domain.ChangeEvent{ScanRunID: run.ID, HostID: "h9", EventType: "NEW_SERVICE", Port: 1000 + i, CreatedAt: now})
	}
	if rep, _ := m.Compact(ctx, RetentionPolicy{ChangesPerHost: 20, Days: 90}); rep.ChangeEvents != 0 {
		t.Fatalf("events of the newest run were removed: %s", rep)
	}

	// The rollup survives an export/import round trip (file store persistence).
	raw, _, err := m.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := newRetentionStore(t)
	if _, _, err := m2.ImportState(raw); err != nil {
		t.Fatal(err)
	}
	if r, _ := m2.GetChangeRollup(ctx, "h1"); r == nil || r.Count != 30 {
		t.Fatalf("rollup after reload: %+v", r)
	}
}

func TestCompactRunScopedHistory(t *testing.T) {
	ctx := context.Background()
	m, _ := newRetentionStore(t)
	base := time.Now().UTC().Add(-48 * time.Hour)
	var ids []string
	for i := 0; i < 15; i++ {
		profile := "nightly"
		if i == 1 || i == 2 {
			profile = "weekly" // only old runs: its newest two keep their snapshots
		}
		status := domain.ScanStatusCompleted
		if i == 0 {
			status = domain.ScanStatusPausedWindow // oldest run, still resumable
		}
		run := &domain.ScanRun{ID: NewID(), ProfileID: profile, Name: fmt.Sprintf("run %d", i), Status: status,
			RawNmapXML: "<nmaprun/>", StartedAt: base.Add(time.Duration(i) * time.Hour)}
		if err := m.CreateScanRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		_ = m.SaveScanChunks(ctx, run.ID, []domain.ScanChunk{{ChunkIndex: 0, Targets: []string{"10.0.0.1", "10.0.0.2"},
			NmapCommands: []string{"nmap -sS 10.0.0.1-2"}, Status: domain.ChunkStatusDone, ActiveHosts: 1}})
		_ = m.SaveScanSnapshot(ctx, run.ID, []domain.Host{{IP: "10.0.0.1"}})
		ids = append(ids, run.ID)
	}
	if ss, ok := any(m).(SettingsStore); ok {
		_ = ss.SaveSetting(ctx, "run_telemetry:"+ids[14], map[string]int{"timeouts": 1})
		_ = ss.SaveSetting(ctx, "run_telemetry:deleted-run", map[string]int{"timeouts": 1})
	}
	for i := 0; i < 30; i++ {
		_ = m.AddAuditLog(ctx, &domain.AuditLog{Username: "admin", Action: fmt.Sprintf("POST %d", i)})
		_ = m.AddDefectDojoExport(ctx, &domain.DefectDojoExport{Title: fmt.Sprintf("export %d", i)})
	}

	rep, err := m.Compact(ctx, RetentionPolicy{SnapshotRuns: 5, RawXMLRuns: 4, ChunkDetailRuns: 3, AuditEntries: 10, ExportEntries: 12})
	if err != nil {
		t.Fatal(err)
	}
	// Snapshots: newest 5 (runs 10..14) plus the weekly profile's runs 1 and 2.
	for i, id := range ids {
		_, err := m.GetScanSnapshot(ctx, id)
		want := i >= 10 || i == 1 || i == 2
		if (err == nil) != want {
			t.Fatalf("run %d snapshot kept=%v, want %v", i, err == nil, want)
		}
	}
	if rep.Snapshots != 8 {
		t.Fatalf("removed %d snapshots", rep.Snapshots)
	}
	// Raw XML and chunk detail: newest N finished runs; the paused run keeps everything.
	for i, id := range ids {
		run, _ := m.GetScanRun(ctx, id)
		wantXML := i >= 11 || i == 0
		if (run.RawNmapXML != "") != wantXML || run.HasRawNmapXML != wantXML {
			t.Fatalf("run %d raw XML kept=%v has=%v, want %v", i, run.RawNmapXML != "", run.HasRawNmapXML, wantXML)
		}
		chunks, _ := m.GetScanChunks(ctx, id)
		wantDetail := i >= 12 || i == 0
		if (len(chunks[0].Targets) > 0) != wantDetail || (len(chunks[0].NmapCommands) > 0) != wantDetail {
			t.Fatalf("run %d chunk detail kept=%v, want %v", i, len(chunks[0].Targets) > 0, wantDetail)
		}
		if chunks[0].ActiveHosts != 1 || chunks[0].Status != domain.ChunkStatusDone {
			t.Fatalf("run %d chunk ledger lost its counters: %+v", i, chunks[0])
		}
	}
	audit, _ := m.ListAuditLogs(ctx, 0)
	exports, _ := m.ListDefectDojoExports(ctx, 0)
	if len(audit) != 10 || audit[0].Action != "POST 29" || len(exports) != 12 || exports[0].Title != "export 29" {
		t.Fatalf("audit %d (newest %q), exports %d", len(audit), audit[0].Action, len(exports))
	}
	if rep.TelemetryDocs != 1 {
		t.Fatalf("orphaned telemetry removed: %d", rep.TelemetryDocs)
	}
	var tel map[string]int
	if found, _ := m.GetSetting(ctx, "run_telemetry:"+ids[14], &tel); !found {
		t.Fatal("telemetry of an existing run was removed")
	}
}

func TestCompactDisabledKeepsEverything(t *testing.T) {
	ctx := context.Background()
	m, _ := newRetentionStore(t)
	for i := 0; i < 5; i++ {
		_ = m.AddAuditLog(ctx, &domain.AuditLog{Action: "x", CreatedAt: time.Now().Add(-400 * 24 * time.Hour)})
		_ = m.AddChangeEvent(ctx, &domain.ChangeEvent{HostID: "h", EventType: "X", CreatedAt: time.Now().Add(-400 * 24 * time.Hour)})
	}
	gen := m.Generation()
	rep, err := m.Compact(ctx, RetentionPolicy{})
	if err != nil || !rep.Empty() || m.Generation() != gen {
		t.Fatalf("disabled policy changed something: %s %v", rep, err)
	}
}

// Stores written by earlier releases hold full, uncompressed snapshots and raw XML: the
// first compaction rewrites the kept ones, even with retention switched off.
func TestCompactMigratesLegacySnapshots(t *testing.T) {
	ctx := context.Background()
	m, vault := newRetentionStore(t)
	run := &domain.ScanRun{ID: NewID(), Name: "old", Status: domain.ScanStatusCompleted, StartedAt: time.Now().UTC()}
	_ = m.CreateScanRun(ctx, run)
	full := []domain.Host{{ID: "h1", IP: "10.0.0.1", LifecycleState: domain.HostStateActive,
		TimeOfDayStats: []domain.TimeSlotStat{{Slot: "00-06", Seen: 3, Total: 4}},
		Services:       []domain.Service{{ID: "s1", Port: 80, Protocol: "tcp", State: "open", Product: "nginx", HTTP: fullFP("Home")}}}}
	legacy, _ := vault.EncryptJSON(full, "scan_snapshots:"+run.ID+":payload")
	xmlEnc, _ := vault.Encrypt("<nmaprun>legacy</nmaprun>", "scan_runs:"+run.ID+":raw_nmap_xml")
	m.mu.Lock()
	m.snapshots[run.ID] = legacy
	row := m.scanRuns[run.ID]
	row.RawNmapXMLEnc = xmlEnc
	m.scanRuns[run.ID] = row
	m.snapshotFormat = 0 // as loaded from an older file
	m.mu.Unlock()

	rep, err := m.Compact(ctx, RetentionPolicy{})
	if err != nil || rep.MigratedSnapshots != 1 {
		t.Fatalf("migration: %s %v", rep, err)
	}
	m.mu.RLock()
	snapPlain, _ := vault.DecryptBytes(m.snapshots[run.ID], "scan_snapshots:"+run.ID+":payload")
	xmlPlain, _ := vault.DecryptBytes(m.scanRuns[run.ID].RawNmapXMLEnc, "scan_runs:"+run.ID+":raw_nmap_xml")
	m.mu.RUnlock()
	if !isGzip(snapPlain) || !isGzip(xmlPlain) {
		t.Fatal("legacy payloads should be compressed after migration")
	}
	hosts, err := m.GetScanSnapshot(ctx, run.ID)
	if err != nil || len(hosts) != 1 || hosts[0].TimeOfDayStats != nil || hosts[0].Services[0].HTTP.Headers != nil ||
		hosts[0].Services[0].HTTP.Title != "Home" || hosts[0].Services[0].Product != "nginx" {
		t.Fatalf("migrated snapshot: %+v %v", hosts, err)
	}
	if got, _ := m.GetScanRun(ctx, run.ID); got.RawNmapXML != "<nmaprun>legacy</nmaprun>" {
		t.Fatalf("migrated raw XML: %q", got.RawNmapXML)
	}
	if rep2, _ := m.Compact(ctx, RetentionPolicy{}); !rep2.Empty() {
		t.Fatalf("migration ran twice: %s", rep2)
	}
}

func TestFileStoreAppliesRetentionOnLoad(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault(testMasterKey)
	path := filepath.Join(t.TempDir(), "store.enc")
	fs, err := OpenFileStore(path, vault, FileStoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		_ = fs.AddAuditLog(ctx, &domain.AuditLog{Username: "admin", Action: fmt.Sprintf("POST /api/v1/x/%d", i),
			Details: map[string]any{"path": fmt.Sprintf("/api/v1/x/%d", i)}})
	}
	fs.Close()
	before, _ := os.Stat(path)

	pol := RetentionPolicy{AuditEntries: 10}
	fs2, err := OpenFileStore(path, vault, FileStoreOptions{Retention: &pol})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if after.Size() >= before.Size() {
		t.Fatalf("compacted store was not written back on load: %d -> %d bytes", before.Size(), after.Size())
	}
	fs2.Close()
	fs3, err := OpenFileStore(path, vault, FileStoreOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if logs, _ := fs3.ListAuditLogs(ctx, 0); len(logs) != 10 {
		t.Fatalf("audit entries after reopen: %d", len(logs))
	}
}
