package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Opt-in: DZIECIOL_TEST_DATABASE_URL=postgres://... go test ./internal/db -run Postgres
// Retention is global, so run it against a scratch database.
func TestPostgresRetention(t *testing.T) {
	url := os.Getenv("DZIECIOL_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set DZIECIOL_TEST_DATABASE_URL to run against PostgreSQL")
	}
	ctx := context.Background()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(ctx, url, vault)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	ip := fmt.Sprintf("10.250.%d.%d", now.UnixNano()%250, now.UnixNano()/250%250)
	h, err := s.UpsertObservedHost(ctx, &domain.Host{IP: ip, LifecycleState: domain.HostStateActive, FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := s.UpsertObservedService(ctx, &domain.Service{HostID: h.ID, HostIP: ip, Port: 80, State: "open", FirstSeen: now, LastSeen: now})
	if err != nil {
		t.Fatal(err)
	}

	var runs []string
	for i := 0; i < 8; i++ {
		profile, status := "pg-ret-a", domain.ScanStatusCompleted
		if i < 2 {
			profile = "pg-ret-b"
		}
		if i == 0 {
			status = domain.ScanStatusPausedWindow
		}
		run := &domain.ScanRun{ID: NewID(), ProfileID: profile, Name: fmt.Sprintf("ret %d", i), RunType: domain.ScanTypeActive,
			Status: status, RawNmapXML: "<nmaprun/>", StartedAt: now.Add(time.Duration(i-10) * time.Minute)}
		if err := s.CreateScanRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveScanChunks(ctx, run.ID, []domain.ScanChunk{{ChunkIndex: 0, Targets: []string{ip}, NmapCommands: []string{"nmap " + ip},
			Status: domain.ChunkStatusDone, ActiveHosts: 1}}); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveScanSnapshot(ctx, run.ID, []domain.Host{{IP: ip}}); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run.ID)
	}
	for i := 39; i >= 0; i-- {
		if err := s.AddObservation(ctx, &ServiceObservation{ScanRunID: runs[7], HostID: h.ID, ServiceID: svc.ID, Port: 80, State: "open",
			ObservedAt: now.Add(-time.Duration(i)*24*time.Hour - time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 50; i++ {
		if err := s.AddChangeEvent(ctx, &domain.ChangeEvent{ScanRunID: "old-run", HostID: h.ID, HostIP: ip, EventType: "HOST_MISSING",
			Severity: "low", CreatedAt: now.Add(-time.Duration(i+1) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 25; i++ { // one scan, many events: the newest run is protected
		_ = s.AddChangeEvent(ctx, &domain.ChangeEvent{ScanRunID: runs[7], HostID: h.ID, HostIP: ip, EventType: "NEW_SERVICE", Port: 1000 + i, CreatedAt: now})
	}
	for i := 0; i < 8; i++ {
		_ = s.AddAuditLog(ctx, &domain.AuditLog{Username: "admin", Action: "POST /x", Status: "success"})
		_ = s.AddDefectDojoExport(ctx, &domain.DefectDojoExport{ExportType: "finding", Title: "x", Status: "success"})
	}
	_ = s.SaveSetting(ctx, "run_telemetry:"+runs[7], map[string]int{"timeouts": 1})
	_ = s.SaveSetting(ctx, "run_telemetry:gone-"+NewID(), map[string]int{"timeouts": 1})

	pol := RetentionPolicy{ObservationsPerService: 25, Days: 10, ChangesPerHost: 20, SnapshotRuns: 3, RawXMLRuns: 2,
		ChunkDetailRuns: 2, AuditEntries: 5, ExportEntries: 5}
	rep, err := s.Compact(ctx, pol)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	t.Logf("report: %s", rep)

	obs, _ := s.ListServiceObservations(ctx, svc.ID, 0)
	if len(obs) != 10 {
		t.Fatalf("observations kept: %d, want the 10 within 10 days", len(obs))
	}
	events, _ := s.ListChangeEvents(ctx, ChangeFilter{HostID: h.ID, Limit: 1000})
	if len(events) != 25 {
		t.Fatalf("change events kept: %d, want the 25 of the protected newest run", len(events))
	}
	roll, err := s.GetChangeRollup(ctx, h.ID)
	if err != nil || roll == nil || roll.Count != 50 || roll.ByType["HOST_MISSING"] != 50 || roll.BySeverity["low"] != 50 {
		t.Fatalf("rollup: %+v %v", roll, err)
	}
	for i, id := range runs {
		_, err := s.GetScanSnapshot(ctx, id)
		wantSnap := i >= 5 || i <= 1 // newest 3, plus the newest 2 of profile b
		if (err == nil) != wantSnap {
			t.Fatalf("run %d snapshot kept=%v want %v", i, err == nil, wantSnap)
		}
		run, _ := s.GetScanRun(ctx, id)
		wantXML := i >= 6 || i == 0 // newest 2, plus the paused run
		if run.HasRawNmapXML != wantXML || (run.RawNmapXML != "") != wantXML {
			t.Fatalf("run %d raw XML kept=%v want %v", i, run.HasRawNmapXML, wantXML)
		}
		chunks, _ := s.GetScanChunks(ctx, id)
		if (len(chunks[0].Targets) > 0) != wantXML || (len(chunks[0].NmapCommands) > 0) != wantXML || chunks[0].ActiveHosts != 1 {
			t.Fatalf("run %d chunk detail: %+v", i, chunks[0])
		}
	}
	if logs, _ := s.ListAuditLogs(ctx, 0); len(logs) != 5 {
		t.Fatalf("audit entries: %d", len(logs))
	}
	if exps, _ := s.ListDefectDojoExports(ctx, 1000); len(exps) != 5 {
		t.Fatalf("export entries: %d", len(exps))
	}
	var tel map[string]int
	if found, _ := s.GetSetting(ctx, "run_telemetry:"+runs[7], &tel); !found {
		t.Fatal("telemetry of an existing run was removed")
	}
	if rep.TelemetryDocs < 1 {
		t.Fatalf("orphaned telemetry not removed: %s", rep)
	}
	// Idempotent: a second pass removes nothing more for this data.
	rep2, err := s.Compact(ctx, pol)
	if err != nil || rep2.Observations != 0 || rep2.ChangeEvents != 0 || rep2.Snapshots != 0 || rep2.RawNmapXML != 0 || rep2.ChunkDetails != 0 {
		t.Fatalf("second pass: %s %v", rep2, err)
	}
	if err := s.DeleteHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.GetChangeRollup(ctx, h.ID); r != nil {
		t.Fatal("rollup of a deleted host remains")
	}
}
