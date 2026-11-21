package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// TestConcurrentAPICallsDuringRunningScan hammers the real API + LiveScanRunner with edits,
// imports, exports, listing and pause/resume/stop/delete races while a scan is running.
// Run with -race. Expectations: no 5xx, no panic, state readable and consistent afterwards.
func TestConcurrentAPICallsDuringRunningScan(t *testing.T) {
	ctx := context.Background()
	vault, _ := crypto.NewVault("")
	store := db.NewMemoryStore(vault)
	if err := db.SeedDefaults(ctx, store, true); err != nil {
		t.Fatal(err)
	}
	hub := api.NewSSEHub()
	pipeline := ingest.NewPipeline(store, NewIntelligenceAnalyzer(), hub.Publish)
	runner := NewLiveScanRunner(store, pipeline, hub)
	runner.engineConfig = func(cfg scanner.EngineConfig) scanner.EngineConfig {
		cfg.UseNmap = false
		cfg.MaxChunkWorkers = 2
		cfg.DisableAdaptiveChunking = true
		cfg.WindowPollInterval = 5 * time.Millisecond
		cfg.CustomDiscoveryFn = func(ctx context.Context, ips []string) ([]string, error) {
			select {
			case <-time.After(20 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return ips[:2], nil
		}
		cfg.CustomServiceScanFn = func(ctx context.Context, ips []string, ports []int) (map[string][]domain.ObservedService, string, error) {
			m := map[string][]domain.ObservedService{}
			for _, ip := range ips {
				m[ip] = []domain.ObservedService{{Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh"}}
			}
			return m, "", nil
		}
		return cfg
	}
	srv := api.NewServer(api.Config{JWTSecret: vault.JWTSecret(""), SeedDemo: true}, store, vault, pipeline, runner, hub)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	call := func(method, path, tok string, body any) (int, []byte) {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req, _ := http.NewRequest(method, ts.URL+path, rdr)
		req.Header.Set("Content-Type", "application/json")
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("%s %s: %v", method, path, err)
			return 0, nil
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	_, lb := call("POST", "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "Admin123!"})
	var login struct{ Token string }
	_ = json.Unmarshal(lb, &login)
	tok := login.Token
	if tok == "" {
		t.Fatal("login failed")
	}

	// Seed one host to edit.
	if code, b := call("POST", "/api/v1/ingest/manual", tok, map[string]any{"ip": "10.99.0.1", "port": 22}); code != http.StatusCreated {
		t.Fatalf("manual: %d %s", code, b)
	}
	_, hb := call("GET", "/api/v1/hosts?limit=5", tok, nil)
	var hostList struct {
		Hosts []domain.Host `json:"hosts"`
	}
	_ = json.Unmarshal(hb, &hostList)
	if len(hostList.Hosts) == 0 {
		t.Fatalf("no hosts: %s", hb)
	}
	hostID := hostList.Hosts[0].ID

	code, sb := call("POST", "/api/v1/scans", tok, map[string]any{"name": "chaos", "targets": []string{"10.80.0.0/26"}, "allowed_ports": "22", "chunk_target_sec": 5})
	if code != http.StatusAccepted {
		t.Fatalf("start scan: %d %s", code, sb)
	}
	var run domain.ScanRun
	_ = json.Unmarshal(sb, &run)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var fiveXX []string
	record := func(what string, code int, body []byte) {
		if code >= 500 {
			mu.Lock()
			fiveXX = append(fiveXX, fmt.Sprintf("%s -> %d %s", what, code, body))
			mu.Unlock()
		}
	}
	csv := []byte("ip,port\n10.98.0.1,22\n10.98.0.2,80\n10.99.0.1,443\n")
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				c, b := call("PATCH", "/api/v1/hosts/"+hostID+"/overrides", tok, map[string]any{"notes": fmt.Sprintf("w%d-%d", w, i), "owner": "soc"})
				record("patch", c, b)
				c, b = call("GET", "/api/v1/export?format=json", tok, nil)
				record("export", c, b)
				c, b = call("GET", "/api/v1/hosts?limit=50", tok, nil)
				record("hosts", c, b)
				c, b = call("GET", "/api/v1/dashboard/summary", tok, nil)
				record("dashboard", c, b)

				var buf bytes.Buffer
				mw := multipart.NewWriter(&buf)
				fw, _ := mw.CreateFormFile("file", "x.csv")
				_, _ = fw.Write(csv)
				_ = mw.Close()
				req, _ := http.NewRequest("POST", ts.URL+"/api/v1/ingest/import", &buf)
				req.Header.Set("Content-Type", mw.FormDataContentType())
				req.Header.Set("Authorization", "Bearer "+tok)
				if resp, err := http.DefaultClient.Do(req); err == nil {
					var rb bytes.Buffer
					_, _ = rb.ReadFrom(resp.Body)
					resp.Body.Close()
					record("import", resp.StatusCode, rb.Bytes())
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			for _, op := range []string{"pause", "resume", "pause", "resume"} {
				c, b := call("POST", "/api/v1/scans/"+run.ID+"/"+op, tok, nil)
				record(op, c, b)
			}
		}
		c, b := call("POST", "/api/v1/scans/"+run.ID+"/stop", tok, nil)
		record("stop", c, b)
		c, b = call("DELETE", "/api/v1/scans/"+run.ID, tok, nil)
		record("delete", c, b)
		c, b = call("POST", "/api/v1/scans/"+run.ID+"/resume", tok, nil) // resume a deleted run
		record("resume-deleted", c, b)
	}()
	wg.Wait()

	deadline := time.Now().Add(15 * time.Second)
	for runner.IsScanActive(run.ID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runner.IsScanActive(run.ID) {
		t.Fatal("scan still active after stop+delete")
	}
	if len(fiveXX) > 0 {
		t.Fatalf("%d server errors, first: %s", len(fiveXX), fiveXX[0])
	}
	// State is consistent: host readable, last override stored, export valid JSON.
	h, err := store.GetHost(ctx, hostID)
	if err != nil || h.Owner != "soc" {
		t.Fatalf("host after chaos: %v %+v", err, h)
	}
	_, eb := call("GET", "/api/v1/export?format=json", tok, nil)
	if !json.Valid(eb) {
		t.Fatalf("export is not valid JSON after chaos")
	}
}
