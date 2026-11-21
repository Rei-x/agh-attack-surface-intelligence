package ingest

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestUnifiedCSVIngestDiffOverridePreservationAndExport(t *testing.T) {
	ctx := context.Background()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	store := db.NewMemoryStore(vault)
	pipeline := NewPipeline(store, NewDefaultAnalyzer(), nil)

	// 1. Import CSV (Scan 1)
	csvInput := `ip,hostname,port,protocol,service,product,version,http_title,status_code,headers,cookies,tags,notes
172.28.0.10,cms.agh.edu.pl,80,tcp,http,Apache,2.4.58,AGH WordPress Portal,200,"Server: Apache/2.4.58","wp-settings-1=m5",cms;prod,initial csv import
172.28.0.11,admin.agh.edu.pl,80,tcp,http,Express,4.18,CBI AGH Admin Console,200,"X-Powered-By: Express","admin_session=tok",internal,admin panel host`

	obs1, err := ParseCSV(strings.NewReader(csvInput))
	if err != nil {
		t.Fatalf("ParseCSV: %v", err)
	}
	res1, err := pipeline.ProcessObservations(ctx, IngestRequest{
		RunType:      domain.ScanTypeImportCSV,
		ScanName:     "CSV Baseline",
		TriggeredBy:  "operator",
		Observations: obs1,
	})
	if err != nil {
		t.Fatalf("ProcessObservations CSV: %v", err)
	}
	if res1.HostsProcessed != 2 || res1.ServicesUpserted != 2 || res1.ChangesDetected < 2 {
		t.Fatalf("unexpected res1: %+v", res1)
	}

	// Verify encryption at rest on ingested host
	hAdmin, err := store.GetHostByIP(ctx, "172.28.0.11")
	if err != nil {
		t.Fatalf("GetHostByIP: %v", err)
	}
	if !strings.HasPrefix(store.RawHostIPCiphertext(hAdmin.ID), "enc:v1:") {
		t.Fatalf("expected encrypted IP in store")
	}
	if len(hAdmin.Services) != 1 || !hAdmin.Services[0].IsAdminPanel {
		t.Fatalf("expected admin panel detected on 172.28.0.11, got %+v", hAdmin.Services)
	}

	// 2. Analyst pins override on 172.28.0.11
	if err := store.PatchOverrides(ctx, "host", hAdmin.ID, map[string]any{
		"owner":       "CBI-SOC",
		"environment": "prod",
	}, nil, "analyst"); err != nil {
		t.Fatalf("PatchOverrides: %v", err)
	}

	// 3. Import JSON (Scan 2) with mutated title on 172.28.0.11 + new staging host 172.28.0.12
	jsonInput := `[
		{"ip":"172.28.0.11","hostname":"admin-mutated.agh.edu.pl","port":80,"service":"http","product":"Express","version":"5.0","http_title":"CBI AGH Admin Console v2","status_code":200},
		{"ip":"172.28.0.12","hostname":"staging.agh.edu.pl","port":443,"service":"https","http_title":"Staging USOS Portal","status_code":200,"headers":{"X-Debug-Token":"9f8a7b6c"}}
	]`
	obs2, err := ParseJSON(strings.NewReader(jsonInput))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	res2, err := pipeline.ProcessObservations(ctx, IngestRequest{
		RunType:      domain.ScanTypeImportJSON,
		ScanName:     "JSON Delta",
		TriggeredBy:  "operator",
		Observations: obs2,
	})
	if err != nil {
		t.Fatalf("ProcessObservations JSON: %v", err)
	}
	if res2.ChangesDetected == 0 {
		t.Fatalf("expected diff changes in Scan 2")
	}

	// Verify override survived Scan 2
	hAdminAfter, err := store.GetHostByIP(ctx, "172.28.0.11")
	if err != nil {
		t.Fatalf("GetHostByIP after scan 2: %v", err)
	}
	if hAdminAfter.Owner != "CBI-SOC" || hAdminAfter.Environment != "prod" {
		t.Fatalf("overrides lost across Scan 2: %+v", hAdminAfter)
	}

	// 4. Manual entry goes through the exact same pipeline
	manualHost, err := ParseManual(ManualEntryRequest{
		IP:          "172.28.0.15",
		Hostname:    "manual.agh.edu.pl",
		Port:        8080,
		ServiceName: "http",
		Product:     "HP LaserJet",
		HTTP:        &domain.HTTPFingerprint{Title: "HP LaserJet Pro MFP"},
	})
	if err != nil {
		t.Fatalf("ParseManual: %v", err)
	}
	res3, err := pipeline.ProcessObservations(ctx, IngestRequest{
		RunType:      domain.ScanTypeManual,
		TriggeredBy:  "analyst",
		Observations: []domain.ObservedHost{manualHost},
	})
	if err != nil || res3.HostsProcessed != 1 {
		t.Fatalf("Manual ingest failed: res=%+v err=%v", res3, err)
	}

	// 5. Export CSV & JSON
	hosts, _, _ := store.ListHosts(ctx, db.HostFilter{})
	var csvBuf, jsonBuf bytes.Buffer
	if err := ExportCSV(&csvBuf, hosts); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}
	if !strings.Contains(csvBuf.String(), "172.28.0.15") || !strings.Contains(csvBuf.String(), "CBI-SOC") {
		t.Fatalf("CSV export missing expected data: %s", csvBuf.String())
	}
	if err := ExportJSON(&jsonBuf, hosts); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), "172.28.0.12") {
		t.Fatalf("JSON export missing expected host")
	}
}

// A live scan's run counters are owned by the engine; ingesting a segment must not add the
// pipeline's upsert count on top (that doubled services_found for every live scan).
func TestLiveRunCountersNotDoubleCounted(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	pipeline := NewPipeline(store, NewDefaultAnalyzer(), nil)

	run := &domain.ScanRun{ID: db.NewID(), Name: "live", RunType: domain.ScanTypeActive, Status: domain.ScanStatusRunning,
		ActiveHosts: 1, ServicesFound: 2}
	if err := store.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	obs := []domain.ObservedHost{{IP: "10.66.0.5", IsAlive: true, Services: []domain.ObservedService{
		{Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh"},
		{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"},
	}}}
	if _, err := pipeline.ProcessObservations(ctx, IngestRequest{ScanRunID: run.ID, RunType: domain.ScanTypeActive, Observations: obs}); err != nil {
		t.Fatal(err)
	}
	got, _ := store.GetScanRun(ctx, run.ID)
	if got.ServicesFound != 2 || got.ActiveHosts != 1 {
		t.Fatalf("engine counters changed by ingest: services=%d hosts=%d (want 2/1)", got.ServicesFound, got.ActiveHosts)
	}

	// Imports own their run: counters come from the pipeline.
	res, err := pipeline.ProcessObservations(ctx, IngestRequest{RunType: domain.ScanTypeImportJSON, ScanName: "import", Observations: obs})
	if err != nil {
		t.Fatal(err)
	}
	imp, _ := store.GetScanRun(ctx, res.ScanRun.ID)
	if imp.ServicesFound != 2 || imp.ActiveHosts != 1 {
		t.Fatalf("import counters wrong: services=%d hosts=%d", imp.ServicesFound, imp.ActiveHosts)
	}
}
