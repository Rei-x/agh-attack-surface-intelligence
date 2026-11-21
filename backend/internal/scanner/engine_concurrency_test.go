package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// TestMain lets the test binary impersonate nmap: when AEGIS_FAKE_NMAP_LOG is set the process
// logs its argv + wall-clock interval, sleeps, and prints nmap-style XML. This exercises the
// real exec path (argv building, concurrency, --max-rate split) without network access.
func TestMain(m *testing.M) {
	if logPath := os.Getenv("AEGIS_FAKE_NMAP_LOG"); logPath != "" && len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-test.") {
		os.Exit(fakeNmapMain(logPath, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeNmapMain(logPath string, args []string) int {
	start := time.Now().UnixNano()
	time.Sleep(150 * time.Millisecond)
	end := time.Now().UnixNano()

	var targets []string
	for i := len(args) - 1; i >= 0; i-- {
		if args[i] == "-" { // value of -oX
			break
		}
		targets = append(targets, expandOctetRange(args[i])...)
	}
	isDiscovery := false
	for _, a := range args {
		if a == "-sn" {
			isDiscovery = true
		}
	}
	var hosts []domain.ObservedHost
	for _, ip := range targets {
		h := domain.ObservedHost{IP: ip, IsAlive: true}
		if !isDiscovery {
			h.Services = []domain.ObservedService{{Port: 80, Protocol: "tcp", State: "open", ServiceName: "http"}}
		}
		hosts = append(hosts, h)
	}
	fmt.Print(GenerateNmapXML(hosts, "nmap "+strings.Join(args, " "), time.Unix(0, start), time.Unix(0, end)))

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 2
	}
	defer f.Close()
	fmt.Fprintf(f, "%d %d %s\n", start, end, strings.Join(args, " "))
	return 0
}

func expandOctetRange(s string) []string {
	dot := strings.LastIndex(s, ".")
	if dot < 0 {
		return []string{s}
	}
	base, last := s[:dot+1], s[dot+1:]
	if lo, hi, ok := strings.Cut(last, "-"); ok {
		a, _ := strconv.Atoi(lo)
		b, _ := strconv.Atoi(hi)
		var out []string
		for i := a; i <= b; i++ {
			out = append(out, base+strconv.Itoa(i))
		}
		return out
	}
	return []string{s}
}

type fakeCall struct {
	start, end int64
	args       []string
}

func readFakeLog(t *testing.T, path string) []fakeCall {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake nmap log: %v", err)
	}
	var calls []fakeCall
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 {
			continue
		}
		s, _ := strconv.ParseInt(parts[0], 10, 64)
		e, _ := strconv.ParseInt(parts[1], 10, 64)
		calls = append(calls, fakeCall{start: s, end: e, args: strings.Fields(parts[2])})
	}
	return calls
}

func argValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

// maxRateOverlap returns the maximum, over time, of the summed --max-rate of nmap processes
// running at that instant, and the maximum number of overlapping processes.
func maxRateOverlap(calls []fakeCall) (maxSum, maxProcs int) {
	type ev struct {
		t    int64
		rate int
	}
	var evs []ev
	for _, c := range calls {
		r, _ := strconv.Atoi(argValue(c.args, "--max-rate"))
		evs = append(evs, ev{c.start, r}, ev{c.end, -r})
	}
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].t == evs[j].t {
			return evs[i].rate < evs[j].rate // process ends before next starts
		}
		return evs[i].t < evs[j].t
	})
	sum, procs := 0, 0
	for _, e := range evs {
		sum += e.rate
		if e.rate > 0 {
			procs++
		} else {
			procs--
		}
		if sum > maxSum {
			maxSum = sum
		}
		if procs > maxProcs {
			maxProcs = procs
		}
	}
	return maxSum, maxProcs
}

func TestChunkWorkerPlanSplitsGlobalRate(t *testing.T) {
	cases := []struct {
		maxW, conc, rate, pending int
		wantW, wantRate           int
	}{
		{4, 32, 400, 10, 4, 100},
		{4, 2, 400, 10, 2, 200},     // bounded by profile concurrency
		{8, 32, 50, 10, 2, 25},      // bounded by MinWorkerRatePPS (50/20 = 2)
		{4, 32, 1000, 3, 3, 333},    // bounded by pending chunks
		{4, 32, 10, 10, 1, 10},      // tiny budget -> single worker
		{16, 64, 1500, 100, 16, 93}, // 16*93 = 1488 <= 1500
	}
	for _, c := range cases {
		w, r := ChunkWorkerPlan(c.maxW, c.conc, c.rate, c.pending)
		if w != c.wantW || r != c.wantRate {
			t.Errorf("ChunkWorkerPlan(%d,%d,%d,%d) = (%d,%d), want (%d,%d)", c.maxW, c.conc, c.rate, c.pending, w, r, c.wantW, c.wantRate)
		}
		if w*r > c.rate {
			t.Errorf("total rate %d exceeds cap %d", w*r, c.rate)
		}
	}
}

func TestConcurrentChunkWorkersHonorTotalRateCapWithRealExec(t *testing.T) {
	logPath := t.TempDir() + "/fake-nmap.log"
	t.Setenv("AEGIS_FAKE_NMAP_LOG", logPath)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	opts := DefaultNmapOptions()
	runner := &NmapRunner{UseNmap: true, NmapBinary: self, Options: &opts, Concurrency: 8}
	eng := NewEngine(EngineConfig{NmapRunner: runner, MaxChunkWorkers: 4, DisableAdaptiveChunking: true})

	profile := domain.ScanProfile{
		ID: "p-conc", Name: "conc", Targets: []string{"10.30.0.0/24"}, AllowedPorts: "80,8081",
		MaxRatePPS: 400, Concurrency: 32, ChunkTargetSec: 30,
	}
	run, res, err := eng.PrepareRun(context.Background(), "run-conc", profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	run.Chunks = BuildChunks(run.ID, res.IPs, 32) // 256 IPs -> 8 chunks
	run.TotalChunks = len(run.Chunks)

	var cbMu sync.Mutex
	doneUpdates := 0
	out, err := eng.Execute(context.Background(), run, profile, res, RunCallbacks{
		OnChunkUpdate: func(ch domain.ScanChunk) {
			cbMu.Lock()
			defer cbMu.Unlock()
			if ch.Status == domain.ChunkStatusDone {
				doneUpdates++
			}
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if run.Status != domain.ScanStatusCompleted || run.CompletedChunks != 8 || doneUpdates != 8 {
		t.Fatalf("status=%s completed=%d doneUpdates=%d", run.Status, run.CompletedChunks, doneUpdates)
	}
	// Pool 400 (no HTTP share): 8 service shares are reserved (capped at a quarter of the pool:
	// 8 x 12), discovery workers split the remaining 300 -> 4 x 75.
	if out.ChunkWorkers != 4 || out.PerWorkerRatePPS != 75 {
		t.Fatalf("expected 4 workers x 75 pps, got %d x %d", out.ChunkWorkers, out.PerWorkerRatePPS)
	}

	calls := readFakeLog(t, logPath)
	if len(calls) != 16 { // sweep + service per chunk (unprivileged: no ICMP pass)
		t.Fatalf("expected 16 nmap invocations, got %d", len(calls))
	}
	maxSum, maxProcs := maxRateOverlap(calls)
	if maxProcs < 2 {
		t.Fatalf("chunks did not run concurrently (max overlap %d)", maxProcs)
	}
	// Discovery and service processes overlap in the pipeline; the summed --max-rate of
	// everything running at any instant must stay within the profile cap.
	if maxSum > profile.MaxRatePPS {
		t.Fatalf("concurrent nmap processes exceeded cap: procs=%d summed --max-rate=%d cap=%d", maxProcs, maxSum, profile.MaxRatePPS)
	}
	sweeps, services := 0, 0
	for _, c := range calls {
		joined := strings.Join(c.args, " ")
		if !strings.Contains(joined, "--max-retries") {
			t.Fatalf("unexpected nmap argv: %s", joined)
		}
		if strings.Contains(joined, "-sV") {
			services++
			if r, _ := strconv.Atoi(argValue(c.args, "--max-rate")); r < 1 || r > 12 || !strings.Contains(joined, "--host-timeout") {
				t.Fatalf("service scan argv: %s", joined)
			}
		} else {
			sweeps++
			// A sweep gets its planned 75 pps (the service reserve keeps it from shrinking).
			r, _ := strconv.Atoi(argValue(c.args, "--max-rate"))
			mr, _ := strconv.Atoi(argValue(c.args, "--min-rate"))
			if r < 37 || r > 75 || mr != r*90/100 || !strings.Contains(joined, "-sT -Pn -n -p 80,8081 --max-retries 0") {
				t.Fatalf("sweep argv (every profile port, one probe each, paced): %s", joined)
			}
		}
		if err := ValidateSafeNmapArgs(c.args); err != nil {
			t.Fatal(err)
		}
	}
	if sweeps != 8 || services != 8 {
		t.Fatalf("expected 8 sweeps + 8 service scans, got %d + %d", sweeps, services)
	}
	for _, ch := range run.Chunks {
		if len(ch.NmapCommands) != 2 || !strings.HasPrefix(ch.NmapCommands[0], self) || ch.MaxRatePPS < 37 || ch.MaxRatePPS > 75 || ch.Worker < 1 || ch.Worker > 4 {
			t.Fatalf("chunk %d missing transparency data: %+v", ch.ChunkIndex, ch)
		}
	}
	if len(out.ObservedHosts) != 256 || len(out.ScannedIPs) != 256 {
		t.Fatalf("observed=%d scanned=%d", len(out.ObservedHosts), len(out.ScannedIPs))
	}
	parsed, err := ParseNmapXML([]byte(out.RawNmapXML))
	if err != nil || len(parsed) != 256 {
		t.Fatalf("merged nmap XML: hosts=%d err=%v", len(parsed), err)
	}
}

func TestConcurrentWindowCloseMidScanPausesAndResumesExactlyOnce(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Warsaw")
	if loc == nil {
		loc = time.UTC
	}
	var clockMu sync.Mutex
	cur := time.Date(2026, 11, 20, 5, 50, 0, 0, loc)
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return cur }
	set := func(t time.Time) { clockMu.Lock(); cur = t; clockMu.Unlock() }

	// The first 3 chunks are quick; every later chunk overruns (blocks until killed). The
	// window closes right after the 3rd chunk is DONE, while other chunks are in flight.
	var calls atomic.Int32
	var phase2 atomic.Bool
	var doneCount atomic.Int32
	var scanCountMu sync.Mutex
	scanCount := map[string]int{}
	eng := NewEngine(EngineConfig{
		Now:                     now,
		MaxChunkWorkers:         4,
		WindowPollInterval:      5 * time.Millisecond,
		DisableAdaptiveChunking: true,
		CustomDiscoveryFn: func(ctx context.Context, ips []string) ([]string, error) {
			if phase2.Load() || calls.Add(1) <= 3 {
				time.Sleep(5 * time.Millisecond)
				return ips, nil
			}
			<-ctx.Done() // overrunning "nmap" gets killed when the window closes
			return nil, ctx.Err()
		},
		CustomServiceScanFn: func(ctx context.Context, ips []string, ports []int) (map[string][]domain.ObservedService, string, error) {
			m := map[string][]domain.ObservedService{}
			hosts := make([]domain.ObservedHost, 0, len(ips))
			scanCountMu.Lock()
			for _, ip := range ips {
				scanCount[ip]++
				m[ip] = []domain.ObservedService{{Port: 22, Protocol: "tcp", State: "open", ServiceName: "ssh"}}
				hosts = append(hosts, domain.ObservedHost{IP: ip, IsAlive: true, Services: m[ip]})
			}
			scanCountMu.Unlock()
			return m, GenerateNmapXML(hosts, "", now(), now()), nil
		},
	})
	profile := domain.ScanProfile{
		ID: "p-win", Name: "night", Targets: []string{"10.40.0.0/24"}, AllowedPorts: "22",
		MaxRatePPS: 400, Concurrency: 16, WindowEnabled: true, WindowStart: "22:00", WindowEnd: "06:00",
		Timezone: "Europe/Warsaw",
	}
	run, res, err := eng.PrepareRun(context.Background(), "run-win-conc", profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	run.Chunks = BuildChunks(run.ID, res.IPs, 32) // 8 chunks
	run.TotalChunks = len(run.Chunks)

	closeWindowAfter3 := RunCallbacks{OnChunkUpdate: func(ch domain.ScanChunk) {
		if ch.Status == domain.ChunkStatusDone && doneCount.Add(1) == 3 {
			set(time.Date(2026, 11, 20, 6, 0, 30, 0, loc)) // window closes mid-scan
		}
	}}
	r1, err := eng.Execute(context.Background(), run, profile, res, closeWindowAfter3)
	if err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if !r1.PausedByWindow || run.Status != domain.ScanStatusPausedWindow || run.WindowPausedCount != 1 {
		t.Fatalf("expected PAUSED_WINDOW, got status=%s paused=%v cnt=%d", run.Status, r1.PausedByWindow, run.WindowPausedCount)
	}
	done, pending := 0, 0
	for _, ch := range run.Chunks {
		switch ch.Status {
		case domain.ChunkStatusDone:
			done++
		case domain.ChunkStatusPending:
			pending++
			if ch.StartedAt != nil {
				t.Fatalf("pending chunk %d kept a start time", ch.ChunkIndex)
			}
		default:
			t.Fatalf("chunk %d left in status %s after window pause", ch.ChunkIndex, ch.Status)
		}
	}
	if done == 0 || pending == 0 || done != run.CompletedChunks || len(r1.ScannedIPs) != run.ScannedIPs {
		t.Fatalf("expected partial progress: done=%d pending=%d completed=%d scanned=%d/%d", done, pending, run.CompletedChunks, len(r1.ScannedIPs), run.ScannedIPs)
	}

	// Next night: resume from checkpoint.
	if done != 3 || pending != 5 {
		t.Fatalf("expected 3 done / 5 pending, got %d / %d", done, pending)
	}
	phase2.Store(true)
	set(time.Date(2026, 11, 20, 22, 5, 0, 0, loc))
	r2, err := eng.Execute(context.Background(), run, profile, res, RunCallbacks{})
	if err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if r2.PausedByWindow || run.Status != domain.ScanStatusCompleted || run.CompletedChunks != 8 || run.ScannedIPs != 256 {
		t.Fatalf("resume did not complete: status=%s completed=%d scanned=%d", run.Status, run.CompletedChunks, run.ScannedIPs)
	}
	seen := map[string]bool{}
	for _, ip := range append(append([]string{}, r1.ScannedIPs...), r2.ScannedIPs...) {
		if seen[ip] {
			t.Fatalf("IP %s reported scanned in both windows", ip)
		}
		seen[ip] = true
	}
	if len(seen) != 256 {
		t.Fatalf("coverage gap: %d/256 IPs", len(seen))
	}
	// Services were only recorded for completed chunks; interrupted chunks never reached Stage 2.
	for ip, n := range scanCount {
		if n != 1 {
			t.Fatalf("IP %s service-scanned %d times", ip, n)
		}
	}
	parsed, _ := ParseNmapXML([]byte(r2.RawNmapXML))
	if len(parsed) != 256 {
		t.Fatalf("merged XML across windows has %d hosts", len(parsed))
	}
}

func TestUserCancelWithConcurrentWorkersCheckpoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	eng := NewEngine(EngineConfig{
		MaxChunkWorkers:         3,
		DisableAdaptiveChunking: true,
		CustomDiscoveryFn: func(c context.Context, ips []string) ([]string, error) {
			if calls.Add(1) == 4 {
				cancel()
			}
			select {
			case <-c.Done():
				return nil, c.Err()
			case <-time.After(20 * time.Millisecond):
			}
			return nil, nil
		},
	})
	profile := domain.ScanProfile{ID: "p-u", Name: "u", Targets: []string{"10.50.0.0/24"}, AllowedPorts: "22", MaxRatePPS: 300}
	run, res, _ := eng.PrepareRun(context.Background(), "run-u", profile, nil)
	run.Chunks = BuildChunks(run.ID, res.IPs, 32)
	run.TotalChunks = len(run.Chunks)
	_, err := eng.Execute(ctx, run, profile, res, RunCallbacks{})
	if err == nil || run.Status != domain.ScanStatusStopped {
		t.Fatalf("expected stopped with ctx error, got status=%s err=%v", run.Status, err)
	}
	for _, ch := range run.Chunks {
		if ch.Status == domain.ChunkStatusRunning {
			t.Fatalf("chunk %d left RUNNING", ch.ChunkIndex)
		}
	}
}

func TestRechunkTailFromMeasuredThroughput(t *testing.T) {
	ips := make([]string, 0, 1024)
	for i := 0; i < 1024; i++ {
		ips = append(ips, fmt.Sprintf("10.60.%d.%d", i/256, i%256))
	}
	run := &domain.ScanRun{ID: "r"}
	run.Chunks = BuildChunks("r", ips, 64) // 16 chunks
	now := time.Now()
	run.Chunks[0].Status = domain.ChunkStatusDone
	run.Chunks[0].StartedAt = &now
	// Fast network: 20 hosts/s per worker * 30s target = 600 -> snapped 512.
	old, nw, ok := rechunkTail(run, 1, 20, 30)
	if !ok || old != 64 || nw != 512 {
		t.Fatalf("expected re-chunk 64 -> 512, got %d -> %d ok=%v", old, nw, ok)
	}
	total := 0
	for i, ch := range run.Chunks {
		if ch.ChunkIndex != i || ch.ID != fmt.Sprintf("r-chunk-%04d", i) {
			t.Fatalf("bad index/id at %d: %+v", i, ch)
		}
		total += ch.IPCount
	}
	if total != 1024 || run.TotalChunks != len(run.Chunks) || run.Chunks[0].Status != domain.ChunkStatusDone {
		t.Fatalf("ledger broken after re-chunk: total=%d chunks=%d", total, len(run.Chunks))
	}
	// Similar throughput -> no churn.
	if _, _, ok := rechunkTail(run, 1, 17, 30); ok {
		t.Fatalf("re-chunked without significant throughput change")
	}
}

func TestBuildNmapArgsSafeAndTuned(t *testing.T) {
	o := DefaultNmapOptions()
	d := strings.Join(o.BuildDiscoveryArgs([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.1.7"}, []int{8081}, 75), " ")
	want := "-sn -n -PE -PS21,22,23,25,80,443,445,3389,8080,8081,8443 -PA80,443 --max-retries 1 --host-timeout 20s -T3 --max-rate 75 -oX - 10.0.0.1-3 10.0.1.7"
	if d != want {
		t.Fatalf("discovery argv\n got: %s\nwant: %s", d, want)
	}
	o.VersionIntensity = 3
	o.Timing = -1
	sv := strings.Join(o.BuildServiceArgs([]string{"10.0.0.9"}, []int{22, 443}, 250), " ")
	want = "-sT -sV --version-intensity 3 -Pn -n -p 22,443 --max-retries 2 --host-timeout 3m -T4 --max-rate 250 -oX - 10.0.0.9"
	if sv != want {
		t.Fatalf("service argv\n got: %s\nwant: %s", sv, want)
	}
	for _, bad := range [][]string{{"--script", "vuln"}, {"--script=default"}, {"-sC"}, {"-A"}, {"-O"}, {"--osscan-guess"}} {
		if ValidateSafeNmapArgs(bad) == nil {
			t.Fatalf("unsafe argv %v accepted", bad)
		}
	}
}

func TestNmapOptionsFromEnv(t *testing.T) {
	t.Setenv("ASI_NMAP_PING_ICMP", "false")
	t.Setenv("ASI_NMAP_PING_SYN_PORTS", "22,443")
	t.Setenv("ASI_NMAP_PING_ACK_PORTS", "")
	t.Setenv("ASI_NMAP_HOST_TIMEOUT", "90s")
	t.Setenv("ASI_NMAP_VERSION_INTENSITY", "12") // out of range -> ignored
	t.Setenv("ASI_NMAP_TIMING", "2")
	o := NmapOptionsFromEnv()
	if o.PingICMPEcho || len(o.PingSYNPorts) != 2 || len(o.PingACKPorts) != 0 || o.ServiceHostTimeout != 90*time.Second || o.VersionIntensity != DefaultNmapOptions().VersionIntensity || o.Timing != 2 {
		t.Fatalf("env overrides not applied correctly: %+v", o)
	}
}

func TestCompactIPv4TargetsIsExact(t *testing.T) {
	in := []string{"10.0.0.5", "10.0.0.3", "10.0.0.4", "10.0.0.4", "10.0.1.255", "10.0.2.0", "192.168.1.1", "2001:db8::1"}
	got := CompactIPv4Targets(in)
	want := []string{"10.0.0.3-5", "10.0.1.255", "10.0.2.0", "192.168.1.1", "2001:db8::1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v want %v", got, want)
	}
	var expanded []string
	for _, g := range got {
		if net.ParseIP(g) != nil {
			expanded = append(expanded, g)
			continue
		}
		expanded = append(expanded, expandOctetRange(g)...)
	}
	if len(expanded) != 7 {
		t.Fatalf("compaction changed the target set: %v", expanded)
	}
}
