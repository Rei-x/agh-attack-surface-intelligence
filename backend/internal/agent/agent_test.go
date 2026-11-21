package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/api"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

type testServer struct {
	t     *testing.T
	store *db.MemoryStore
	srv   *api.Server
	http  *httptest.Server
	// failChunks makes chunk uploads answer 503 (server trouble / proxy outage).
	failChunks atomic.Bool
}

func newTestServer(t *testing.T) *testServer {
	t.Helper()
	vault, err := crypto.NewVault("")
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewMemoryStore(vault)
	if err := db.SeedDefaults(context.Background(), store, true); err != nil {
		t.Fatal(err)
	}
	hub := api.NewSSEHub()
	pipeline := ingest.NewPipeline(store, ingest.NewDefaultAnalyzer(), hub.Publish)
	srv := api.NewServer(api.Config{JWTSecret: vault.JWTSecret("")}, store, vault, pipeline, nil, hub)
	ts := &testServer{t: t, store: store, srv: srv}
	h := srv.Handler()
	ts.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ts.failChunks.Load() && strings.HasSuffix(r.URL.Path, "/chunks") {
			http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.http.Close)
	return ts
}

func (ts *testServer) token() string {
	tok, _, err := ts.srv.Agents().CreateEnrollToken(context.Background(), "test-agent", "lab", time.Hour, "admin")
	if err != nil {
		ts.t.Fatal(err)
	}
	return tok
}

// queueRun creates an agent-bound profile and starts it through the scheduler path (run now).
func (ts *testServer) queueRun(agentID string, targets ...string) string {
	ts.t.Helper()
	ctx := context.Background()
	p := &domain.ScanProfile{Name: "remote", Targets: targets, AllowedPorts: "80", MaxRatePPS: 100, ChunkTargetSec: 1,
		AgentID: agentID, MissingThreshold: 1, GracePeriodHours: 1, Enabled: true}
	if err := ts.store.CreateProfile(ctx, p); err != nil {
		ts.t.Fatal(err)
	}
	run := &domain.ScanRun{ID: db.NewID(), ProfileID: p.ID, Name: "remote", RunType: domain.ScanTypeActive, Status: domain.ScanStatusQueued, StartedAt: time.Now().UTC()}
	if err := ts.store.CreateScanRun(ctx, run); err != nil {
		ts.t.Fatal(err)
	}
	if err := ts.srv.Agents().Enqueue(ctx, run, p); err != nil {
		ts.t.Fatal(err)
	}
	return run.ID
}

func (ts *testServer) waitRun(runID string, timeout time.Duration, ok func(*domain.ScanRun) bool) *domain.ScanRun {
	ts.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		run, err := ts.store.GetScanRun(context.Background(), runID)
		if err == nil && ok(run) {
			return run
		}
		if time.Now().After(deadline) {
			ts.t.Fatalf("run %s: condition not reached (last: %+v)", runID, run)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// fakeNetwork: hosts .1-.5 of every /24 are alive with port 80. gate (optional) is called
// before each discovery call and may block.
func fakeNetwork(gate func(ctx context.Context, ips []string) error) func(scanner.EngineConfig) scanner.EngineConfig {
	return func(cfg scanner.EngineConfig) scanner.EngineConfig {
		cfg.UseNmap = false
		cfg.MaxChunkWorkers = 1
		cfg.DisableAdaptiveChunking = true
		cfg.CustomDiscoveryFn = func(ctx context.Context, ips []string) ([]string, error) {
			if gate != nil {
				if err := gate(ctx, ips); err != nil {
					return nil, err
				}
			}
			var alive []string
			for _, ip := range ips {
				last := ip[strings.LastIndex(ip, ".")+1:]
				if len(last) == 1 && last >= "1" && last <= "5" {
					alive = append(alive, ip)
				}
			}
			return alive, nil
		}
		cfg.CustomServiceScanFn = func(ctx context.Context, ips []string, ports []int) (map[string][]domain.ObservedService, string, error) {
			out := map[string][]domain.ObservedService{}
			xml := `<nmaprun>`
			for _, ip := range ips {
				out[ip] = []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http", Product: "nginx"}}
				xml += `<host><address addr="` + ip + `" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>`
			}
			return out, xml + `</nmaprun>`, nil
		}
		return cfg
	}
}

func startAgent(t *testing.T, cfg Config) (*Agent, func() error) {
	t.Helper()
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	return a, func() error {
		cancel()
		err := <-done
		a.Close()
		return err
	}
}

func TestAgentEnrollScanKillResume(t *testing.T) {
	ts := newTestServer(t)
	dir := t.TempDir()

	// First process: scans chunk 0, then blocks inside chunk 1 until it is stopped.
	var calls atomic.Int32
	blockAfterFirst := func(ctx context.Context, ips []string) error {
		if calls.Add(1) > 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}
	cfg := Config{ServerURL: ts.http.URL, Token: ts.token(), DataDir: dir, Version: "test", PollWait: time.Second,
		ProgressEvery: 50 * time.Millisecond, EngineConfig: fakeNetwork(blockAfterFirst), Logf: t.Logf}
	a1, stop1 := startAgent(t, cfg)
	deadline := time.Now().Add(5 * time.Second)
	for a1.AgentID() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	agentID := a1.AgentID()
	if agentID == "" {
		t.Fatal("agent did not enroll")
	}
	// Credential file is private and holds no enrollment token.
	info, err := os.Stat(filepath.Join(dir, stateFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", info, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFileName))
	if strings.Contains(string(raw), cfg.Token) {
		t.Fatal("enrollment token persisted on disk")
	}

	runID := ts.queueRun(agentID, "10.77.0.0/25") // 128 IPs -> 4 chunks of 32
	ts.waitRun(runID, 10*time.Second, func(r *domain.ScanRun) bool { return r.CompletedChunks >= 1 && r.TotalChunks == 4 })
	if err := stop1(); err != nil {
		t.Fatalf("agent 1: %v", err)
	}
	mid := ts.waitRun(runID, 5*time.Second, func(r *domain.ScanRun) bool { return true })
	if mid.Status != domain.ScanStatusRunning || mid.CompletedChunks != 1 {
		t.Fatalf("after stopping the agent mid-scan: status=%s chunks=%d/%d", mid.Status, mid.CompletedChunks, mid.TotalChunks)
	}

	// Restart on the same data dir: no token needed, resumes from the checkpoint.
	cfg.Token = ""
	cfg.EngineConfig = fakeNetwork(nil)
	_, stop2 := startAgent(t, cfg)
	defer stop2()
	final := ts.waitRun(runID, 15*time.Second, func(r *domain.ScanRun) bool { return r.Status == domain.ScanStatusCompleted })
	if final.CompletedChunks != 4 || final.ScannedIPs != 128 || final.ActiveHosts != 5 {
		t.Fatalf("final counters: %+v", final)
	}
	if !final.HasRawNmapXML || !strings.Contains(final.RawNmapXML, "10.77.0.1") {
		t.Fatalf("raw nmap xml not merged: %q", final.RawNmapXML)
	}
	hosts, _, _ := ts.store.ListHosts(context.Background(), db.HostFilter{})
	if len(hosts) != 5 {
		t.Fatalf("hosts: %d", len(hosts))
	}
	for _, h := range hosts {
		if h.TotalScansSeen != 1 {
			t.Fatalf("host %s ingested %d times", h.IP, h.TotalScansSeen)
		}
	}
	ag, _ := ts.srv.Agents().GetAgent(context.Background(), agentID)
	if ag.Status != domain.AgentStatusOnline || ag.Version != "test" || ag.RemoteIP != "127.0.0.1" {
		t.Fatalf("agent record: %+v", ag)
	}
}

func TestAgentRefusesTargetsOutsideAllowlist(t *testing.T) {
	ts := newTestServer(t)
	cfg := Config{ServerURL: ts.http.URL, Token: ts.token(), DataDir: t.TempDir(), Version: "test", PollWait: time.Second,
		AllowCIDRs: []string{"192.168.10.0/24"}, EngineConfig: fakeNetwork(nil), Logf: t.Logf}
	a, stop := startAgent(t, cfg)
	defer stop()
	for a.AgentID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	runID := ts.queueRun(a.AgentID(), "10.77.1.0/28")
	run := ts.waitRun(runID, 10*time.Second, func(r *domain.ScanRun) bool { return r.Status == domain.ScanStatusFailed })
	if !strings.Contains(run.Notes, "refused") || !strings.Contains(run.Notes, "192.168.10.0/24") {
		t.Fatalf("refusal note: %q", run.Notes)
	}
	if hosts, _, _ := ts.store.ListHosts(context.Background(), db.HostFilter{}); len(hosts) != 0 {
		t.Fatal("refused job produced hosts")
	}
}

func TestAgentBuffersResultsWhileServerFails(t *testing.T) {
	ts := newTestServer(t)
	ts.failChunks.Store(true)
	dir := t.TempDir()
	cfg := Config{ServerURL: ts.http.URL, Token: ts.token(), DataDir: dir, Version: "test", PollWait: time.Second,
		ProgressEvery: 50 * time.Millisecond, EngineConfig: fakeNetwork(nil), Logf: t.Logf}
	a, stop := startAgent(t, cfg)
	defer stop()
	for a.AgentID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	runID := ts.queueRun(a.AgentID(), "10.77.2.0/26") // 2 chunks
	// Scanning finishes locally while uploads fail: results wait in the outbox.
	deadline := time.Now().Add(10 * time.Second)
	for a.box.pending() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := a.box.pending(); n < 2 {
		t.Fatalf("outbox holds %d records, want the 2 chunk results", n)
	}
	if run, _ := ts.store.GetScanRun(context.Background(), runID); run.CompletedChunks != 0 {
		t.Fatalf("chunks ingested while uploads fail: %d", run.CompletedChunks)
	}
	ts.failChunks.Store(false)
	run := ts.waitRun(runID, 90*time.Second, func(r *domain.ScanRun) bool { return r.Status == domain.ScanStatusCompleted })
	if run.CompletedChunks != 2 || a.box.pending() != 0 {
		t.Fatalf("after recovery: chunks=%d outbox=%d", run.CompletedChunks, a.box.pending())
	}
}

func TestCheckServerURLRequiresTLS(t *testing.T) {
	for _, c := range []struct {
		url      string
		insecure bool
		ok       bool
	}{
		{"https://dzieciol.example.edu", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"http://localhost:8080", false, true},
		{"http://dzieciol.example.edu", false, false},
		{"http://10.0.0.5:8080", true, true},
		{"ftp://x", true, false},
	} {
		if _, err := checkServerURL(c.url, c.insecure); (err == nil) != c.ok {
			t.Errorf("%s insecure=%v: err=%v", c.url, c.insecure, err)
		}
	}
	if _, err := ParseAllowCIDRs([]string{"10.0.0.0/8, 192.168.1.5", "fd00::/8"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAllowCIDRs([]string{"10.0.0.0/33"}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}
