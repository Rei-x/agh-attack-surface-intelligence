package scanner

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// TestRealNmapEngineAgainstLocalListeners runs the full engine with the real nmap binary
// (unprivileged) against listeners on 127.0.0.1. Opt-in: DZIECIOL_REAL_NMAP=1 go test -run RealNmap -v
func TestRealNmapEngineAgainstLocalListeners(t *testing.T) {
	if os.Getenv("DZIECIOL_REAL_NMAP") != "1" {
		t.Skip("set DZIECIOL_REAL_NMAP=1 to run against the real nmap binary")
	}
	bin, err := exec.LookPath("nmap")
	if err != nil {
		t.Skip("nmap not installed")
	}

	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("Set-Cookie", "PHPSESSID=abc; Path=/")
		_, _ = w.Write([]byte("<html><head><title>AGH Panel Logowania</title></head><body>admin</body></html>"))
	})}
	go func() { _ = srv.Serve(httpLn) }()
	defer srv.Close()

	sshLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := sshLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"))
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	defer sshLn.Close()

	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	sshPort := sshLn.Addr().(*net.TCPAddr).Port
	ports := strconv.Itoa(httpPort) + "," + strconv.Itoa(sshPort)

	opts := DefaultNmapOptions()
	opts.ServiceHostTimeout = 60 * time.Second
	runner := &NmapRunner{UseNmap: true, NmapBinary: bin, Options: &opts, Concurrency: 8,
		ConnectTimeout: time.Second, BannerReadTimeout: time.Second}
	eng := NewEngine(EngineConfig{NmapRunner: runner, MaxChunkWorkers: 4, DisableAdaptiveChunking: true})

	profile := domain.ScanProfile{
		ID: "real", Name: "real-nmap", Targets: []string{"127.0.0.1-8"}, AllowedPorts: ports,
		MaxRatePPS: 400, HTTPRPS: 20, Concurrency: 16, EnableHTTPFingerprint: true,
	}
	run, res, err := eng.PrepareRun(context.Background(), "real-run", profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	run.Chunks = BuildChunks(run.ID, res.IPs, 2) // 4 chunks -> 4 concurrent nmap workers
	run.TotalChunks = len(run.Chunks)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	start := time.Now()
	out, err := eng.Execute(ctx, run, profile, res, RunCallbacks{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	t.Logf("run status=%s chunks=%d workers=%d per-worker --max-rate=%d wall=%s duration_ms=%d hosts/s=%.2f",
		run.Status, run.CompletedChunks, out.ChunkWorkers, out.PerWorkerRatePPS, time.Since(start).Round(time.Millisecond), run.DurationMs, run.HostsPerSec)
	for _, ch := range run.Chunks {
		t.Logf("chunk %d worker=%d rate=%d status=%s targets=%v active=%d services=%d duration=%dms",
			ch.ChunkIndex, ch.Worker, ch.MaxRatePPS, ch.Status, ch.Targets, ch.ActiveHosts, ch.Services, ch.DurationMs)
		for _, c := range ch.NmapCommands {
			t.Logf("    $ %s", c)
		}
	}
	var local *domain.ObservedHost
	for i := range out.ObservedHosts {
		h := out.ObservedHosts[i]
		if h.IsAlive {
			t.Logf("alive %s", h.IP)
			for _, s := range h.Services {
				title := ""
				if s.HTTP != nil {
					title = s.HTTP.Title
				}
				t.Logf("    %d/%s %s product=%q version=%q banner=%q http_title=%q", s.Port, s.Protocol, s.ServiceName, s.Product, s.Version, s.Banner, title)
			}
		}
		if h.IP == "127.0.0.1" {
			local = &out.ObservedHosts[i]
		}
	}
	if run.Status != domain.ScanStatusCompleted || local == nil || !local.IsAlive || len(local.Services) != 2 {
		t.Fatalf("expected 127.0.0.1 alive with 2 services, got %+v", local)
	}
	for _, ch := range run.Chunks {
		if len(ch.NmapCommands) == 0 || !strings.HasPrefix(ch.NmapCommands[0], bin) {
			t.Fatalf("chunk %d did not run real nmap: %v", ch.ChunkIndex, ch.NmapCommands)
		}
	}
	if !strings.Contains(out.RawNmapXML, `portid="`+strconv.Itoa(httpPort)+`"`) {
		t.Fatalf("merged nmap XML missing the HTTP port")
	}
}
