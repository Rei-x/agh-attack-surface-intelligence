package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Opt-in: ASI_TEST_DATABASE_URL=postgres://... go test ./internal/db -run Postgres
func TestPostgresScheduleStateAndChunkCommandsRoundTrip(t *testing.T) {
	url := os.Getenv("ASI_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set ASI_TEST_DATABASE_URL to run against PostgreSQL")
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
	// Migrations must be idempotent (they run on every boot).
	if err := s.migrate(ctx); err != nil {
		t.Fatalf("re-run migration: %v", err)
	}

	anchor := time.Now().UTC().Truncate(time.Second)
	st := &domain.ScheduleState{ProfileID: "pg-prof", Cron: "0 22 * * *", AnchorAt: &anchor, LastFireAt: &anchor, LastRunID: "r1",
		LastSkipAt: &anchor, LastSkipReason: "slot skipped: previous run still RUNNING"}
	if err := s.SaveScheduleState(ctx, st); err != nil {
		t.Fatal(err)
	}
	st.LastRunID = "r2"
	if err := s.SaveScheduleState(ctx, st); err != nil { // upsert
		t.Fatal(err)
	}
	list, err := s.ListScheduleStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *domain.ScheduleState
	for i := range list {
		if list[i].ProfileID == "pg-prof" {
			got = &list[i]
		}
	}
	if got == nil || got.LastRunID != "r2" || got.AnchorAt == nil || !got.AnchorAt.Equal(anchor) || got.LastSkipReason == "" {
		t.Fatalf("schedule state roundtrip: %+v", got)
	}

	run := &domain.ScanRun{ID: NewID(), Name: "pg", RunType: domain.ScanTypeActive, Status: domain.ScanStatusRunning, StartedAt: time.Now().UTC()}
	if err := s.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	defer s.DeleteScanRun(ctx, run.ID)
	chunks := []domain.ScanChunk{{ID: run.ID + "-c0", ScanRunID: run.ID, ChunkIndex: 0, Targets: []string{"10.0.0.1"}, IPCount: 1,
		Status: domain.ChunkStatusDone, NmapCommands: []string{"/usr/bin/nmap -sn -n -PE 10.0.0.1"}, MaxRatePPS: 125, Worker: 3}}
	if err := s.SaveScanChunks(ctx, run.ID, chunks); err != nil {
		t.Fatal(err)
	}
	chunks[0].NmapCommands = append(chunks[0].NmapCommands, "/usr/bin/nmap -sT -sV 10.0.0.1")
	if err := s.UpdateScanChunk(ctx, &chunks[0]); err != nil {
		t.Fatal(err)
	}
	back, err := s.GetScanChunks(ctx, run.ID)
	if err != nil || len(back) != 1 || len(back[0].NmapCommands) != 2 || back[0].MaxRatePPS != 125 || back[0].Worker != 3 {
		t.Fatalf("chunk roundtrip: %+v err=%v", back, err)
	}
}
