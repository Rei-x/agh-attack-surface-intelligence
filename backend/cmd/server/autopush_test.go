package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestAutoPushDefectDojoAfterCompletedRun(t *testing.T) {
	var mu sync.Mutex
	var calls []map[string]string
	dd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/reimport-scan/" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseMultipartForm(1 << 20)
		mu.Lock()
		calls = append(calls, map[string]string{
			"scan_type":  r.FormValue("scan_type"),
			"test_title": r.FormValue("test_title"),
			"version":    r.FormValue("version"),
		})
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"test":9,"engagement_id":1,"statistics":{"after":{"total":{"total":2}}}}`))
	}))
	defer dd.Close()

	ctx := context.Background()
	vault, err := crypto.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewMemoryStore(vault)
	runner := NewLiveScanRunner(store, nil, nil)

	profile := &domain.ScanProfile{Name: "Kampus nocny", Targets: []string{"10.0.0.0/24"}}
	if err := store.CreateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	run := &domain.ScanRun{ID: db.NewID(), ProfileID: profile.ID, Name: "Run #7", Status: domain.ScanStatusCompleted,
		RawNmapXML: `<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/><hostnames/></host></nmaprun>`}
	if err := store.CreateScanRun(ctx, run); err != nil {
		t.Fatal(err)
	}

	// Both switches off: nothing is sent (auto_push_findings defaults to on).
	_ = store.SaveDefectDojoConfig(ctx, &domain.DefectDojoConfig{URL: dd.URL, APIToken: "t", AutoPushNmap: false})
	_ = db.SaveDefectDojoOptions(ctx, store, &domain.DefectDojoConfig{AutoPushFindings: false})
	runner.autoPushDefectDojo(ctx, run.ID)
	if len(calls) != 0 {
		t.Fatalf("auto push disabled but DefectDojo was called: %+v", calls)
	}

	_ = store.SaveDefectDojoConfig(ctx, &domain.DefectDojoConfig{URL: dd.URL, APIToken: "t", AutoPushNmap: true})
	_ = db.SaveDefectDojoOptions(ctx, store, &domain.DefectDojoConfig{AutoPushFindings: true})
	runner.autoPushDefectDojo(ctx, run.ID)
	// Raw Nmap XML first, then the actionable "Dzięcioł changes" Generic Findings test.
	if len(calls) != 2 || calls[0]["scan_type"] != "Nmap Scan" || calls[0]["test_title"] != "Dzięcioł Nmap: Kampus nocny" || calls[0]["version"] != "Run #7" ||
		calls[1]["scan_type"] != "Generic Findings Import" || calls[1]["test_title"] != "Dzięcioł changes: Kampus nocny" {
		t.Fatalf("unexpected DefectDojo calls: %+v", calls)
	}
	exports, _ := store.ListDefectDojoExports(ctx, 10)
	if len(exports) != 2 {
		t.Fatalf("both pushes must be recorded: %+v", exports)
	}
	for _, e := range exports {
		if e.Status != "success" || e.ExportedBy != "auto-push" || e.ExternalID != "9" {
			t.Fatalf("export not recorded: %+v", exports)
		}
	}

	// Window-paused or failed runs are never pushed.
	run.Status = domain.ScanStatusPausedWindow
	_ = store.UpdateScanRun(ctx, run)
	runner.autoPushDefectDojo(ctx, run.ID)
	if len(calls) != 2 {
		t.Fatalf("paused run must not be pushed: %+v", calls)
	}
}
