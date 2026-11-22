// Command storebench builds a synthetic encrypted file store that resembles a long-running
// lab installation (a /18 with ~1 500 live hosts, ~4 000 services, dozens of full and partial
// scan runs with flapping hosts and services) and measures what the store costs: snapshot
// size, heap after load and peak heap / RSS while one more scan is ingested. It drives the
// real ingest pipeline and the real FileStore, so the numbers follow the product code. It is
// a development tool, not part of the product.
//
//	go run ./cmd/storebench gen    -dir /tmp/sb -hosts 1500 -runs 30
//	go run ./cmd/storebench load   -dir /tmp/sb -heapprofile /tmp/sb/load.pprof
//	go run ./cmd/storebench ingest -dir /tmp/sb -heapprofile /tmp/sb/ingest.pprof
//	go run ./cmd/storebench stats  -dir /tmp/sb
//
// load and ingest open the store read-write (like `dzieciol serve`), so they also apply
// whatever happens on open. Run each subcommand in its own process for clean heap numbers.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/crypto"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// benchKey is a fixed master key so the store can be reopened by every subcommand.
const benchKey = "5ec7e7b0c1d2a3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c"

const storeFile = "dzieciol-store.enc"
const metaFile = "storebench.json"

type meta struct {
	Hosts     int       `json:"hosts"`
	Runs      int       `json:"runs"`
	FullEvery int       `json:"full_every"`
	Flap      float64   `json:"flap"`
	Seed      int64     `json:"seed"`
	Base      time.Time `json:"base"`
	// Every is the time between two runs (3h: a busy lab day; 24h: daily scanning).
	Every time.Duration `json:"every"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: storebench gen|load|ingest|stats [flags]")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "", "store directory")
	hosts := fs.Int("hosts", 1500, "live hosts in the /18 (gen)")
	runs := fs.Int("runs", 30, "scan runs to simulate (gen)")
	fullEvery := fs.Int("full-every", 5, "every Nth run scans the whole /18, the others one /22 (gen)")
	flap := fs.Float64("flap", 0.10, "share of hosts that answer only some of the time (gen)")
	seed := fs.Int64("seed", 1, "random seed (gen)")
	every := fs.Duration("every", 3*time.Hour, "time between two runs (gen)")
	heapProfile := fs.String("heapprofile", "", "write a heap profile here (load, ingest)")
	jsonOut := fs.Bool("json", false, "print the measurement as JSON")
	useRetention := fs.Bool("retention", true, "apply the history retention policy (DZIECIOL_RETENTION_* env, defaults otherwise) on open and after every ingest, like dzieciol serve")
	_ = fs.Parse(args)
	if *useRetention {
		pol := db.RetentionFromEnv()
		retention = &pol
		log.Printf("retention: %s", pol)
	}
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	log.SetFlags(log.Ltime)
	var err error
	switch cmd {
	case "gen":
		err = cmdGen(*dir, meta{Hosts: *hosts, Runs: *runs, FullEvery: *fullEvery, Flap: *flap, Seed: *seed, Every: *every})
	case "load":
		err = cmdLoad(*dir, *heapProfile, *jsonOut)
	case "ingest":
		err = cmdIngest(*dir, *heapProfile, *jsonOut)
	case "stats":
		err = cmdStats(*dir)
	default:
		err = fmt.Errorf("unknown subcommand %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// retention is the policy applied like `dzieciol serve` does (nil with -retention=false).
var retention *db.RetentionPolicy

func newPipeline(store db.Store) *ingest.Pipeline {
	p := ingest.NewPipeline(store, ingest.NewDefaultAnalyzer(), nil)
	if retention != nil {
		p.SetRetention(*retention)
	}
	return p
}

// ---------- synthetic lab ----------

type uService struct {
	Port    int
	Name    string
	Product string
	Version string
	Banner  string
	HTTP    bool
	TLS     bool
	Title   string
	Closed  bool
}

type uHost struct {
	IP       string
	Hostname string
	OS       string
	Flappy   bool
	Birth    int // first run the host exists in
	Death    int // first run the host no longer exists in (0 = never)
	Services []uService
}

type lab struct {
	m     meta
	hosts []*uHost
}

var serviceTemplates = []uService{
	{Port: 22, Name: "ssh", Product: "OpenSSH", Version: "8.9p1 Ubuntu 3ubuntu0.6", Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
	{Port: 80, Name: "http", Product: "nginx", Version: "1.18.0", HTTP: true, Title: "Welcome to nginx!"},
	{Port: 443, Name: "https", Product: "Apache httpd", Version: "2.4.52", HTTP: true, TLS: true, Title: "Wydzial - strona glowna"},
	{Port: 8080, Name: "http", Product: "Apache Tomcat", Version: "9.0.58", HTTP: true, Title: "Apache Tomcat/9.0.58"},
	{Port: 3306, Name: "mysql", Product: "MySQL", Version: "8.0.36", Banner: "J\x00\x00\x008.0.36-0ubuntu0.22.04.1"},
	{Port: 445, Name: "microsoft-ds", Product: "Samba smbd", Version: "4.15.13"},
	{Port: 3389, Name: "ms-wbt-server", Product: "Microsoft Terminal Services"},
	{Port: 9100, Name: "jetdirect", Product: "HP JetDirect"},
	{Port: 8443, Name: "https-alt", Product: "Jetty", Version: "9.4.53", HTTP: true, TLS: true, Title: "Grafana"},
	{Port: 5432, Name: "postgresql", Product: "PostgreSQL DB", Version: "14.11"},
}

func newLab(m meta) *lab {
	rng := rand.New(rand.NewSource(m.Seed))
	l := &lab{m: m}
	used := map[int]bool{}
	for len(l.hosts) < m.Hosts {
		off := 1 + rng.Intn(16382)
		if used[off] {
			continue
		}
		used[off] = true
		h := &uHost{IP: fmt.Sprintf("10.66.%d.%d", off/256, off%256), Flappy: rng.Float64() < m.Flap}
		if rng.Float64() < 0.5 {
			h.Hostname = fmt.Sprintf("srv-%d-%d.lab.agh.edu.pl", off/256, off%256)
		}
		if rng.Float64() < 0.3 {
			h.OS = "Linux 5.4 - 5.15"
		}
		if m.Runs > 2 && rng.Float64() < 0.05 {
			h.Birth = 1 + rng.Intn(m.Runs-1)
		}
		if m.Runs > 2 && rng.Float64() < 0.03 {
			h.Death = h.Birth + 1 + rng.Intn(m.Runs)
		}
		// 1..5 services, ~2.7 on average.
		n := 1 + rng.Intn(3)
		if rng.Float64() < 0.35 {
			n += 2
		}
		seen := map[int]bool{}
		for len(h.Services) < n {
			t := serviceTemplates[rng.Intn(len(serviceTemplates))]
			if seen[t.Port] {
				continue
			}
			seen[t.Port] = true
			h.Services = append(h.Services, t)
		}
		l.hosts = append(l.hosts, h)
	}
	return l
}

// evolve applies run r's random drift: version bumps, new titles, ports closing/reopening.
func (l *lab) evolve(r int) {
	rng := rand.New(rand.NewSource(l.m.Seed*1000 + int64(r)))
	for _, h := range l.hosts {
		for i := range h.Services {
			s := &h.Services[i]
			switch x := rng.Float64(); {
			case x < 0.01:
				s.Version += fmt.Sprintf(".%d", r)
			case x < 0.02 && s.HTTP:
				s.Title = fmt.Sprintf("%s (build %d)", strings.SplitN(s.Title, " (build", 2)[0], r)
			case x < 0.035:
				s.Closed = !s.Closed
			}
		}
	}
}

func (l *lab) runTime(r int) time.Time {
	every := l.m.Every
	if every <= 0 {
		every = 3 * time.Hour
	}
	return l.m.Base.Add(time.Duration(r) * every)
}

// scope returns the IPs scanned by run r: the whole /18, or one rotating /22.
func (l *lab) scope(r int) (string, []string) {
	if l.m.FullEvery > 0 && r%l.m.FullEvery == 0 {
		return "10.66.0.0/18", ipRange(0, 64)
	}
	blk := r % 16
	return fmt.Sprintf("10.66.%d.0/22", blk*4), ipRange(blk*4, blk*4+4)
}

func ipRange(from, to int) []string {
	out := make([]string, 0, (to-from)*256)
	for c := from; c < to; c++ {
		for d := 0; d < 256; d++ {
			out = append(out, fmt.Sprintf("10.66.%d.%d", c, d))
		}
	}
	return out
}

func httpFP(h *uHost, s *uService) *domain.HTTPFingerprint {
	scheme := "http"
	if s.TLS {
		scheme = "https"
	}
	fp := &domain.HTTPFingerprint{
		URL:          fmt.Sprintf("%s://%s:%d/", scheme, h.IP, s.Port),
		Scheme:       scheme,
		StatusCode:   200,
		Title:        s.Title,
		ServerHeader: s.Product + "/" + s.Version,
		Headers: map[string]string{
			"Server":            s.Product + "/" + s.Version,
			"Content-Type":      "text/html; charset=UTF-8",
			"Cache-Control":     "no-store, no-cache, must-revalidate",
			"Pragma":            "no-cache",
			"Expires":           "Thu, 19 Nov 1981 08:52:00 GMT",
			"Vary":              "Accept-Encoding",
			"X-Powered-By":      "PHP/8.1.2-1ubuntu2.14",
			"Set-Cookie":        "PHPSESSID=8f2c1d7e9a0b3c4d5e6f7a8b9c0d1e2f; path=/",
			"Content-Length":    "10918",
			"Connection":        "keep-alive",
			"Accept-Ranges":     "bytes",
			"Last-Modified":     "Mon, 13 Nov 2023 10:14:51 GMT",
			"ETag":              "\"2aa6-60a0717dd8b2c\"",
			"X-Frame-Options":   "SAMEORIGIN",
			"X-Content-Type-Op": "nosniff",
		},
		MissingSecHeaders:  []string{"Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"},
		InterestingHeaders: []string{"X-Powered-By: PHP/8.1.2-1ubuntu2.14"},
		Cookies: []domain.CookieInfo{{Name: "PHPSESSID", Path: "/", HttpOnly: false, Secure: false,
			Flags: []string{"missing_httponly", "missing_secure", "missing_samesite"}}},
		FaviconMMH3:      "-1137974215",
		FaviconSHA256:    "4f1ba7b4d1c5e9a9c4e2c62f6d6e1c3b8a7f5e4d3c2b1a0f9e8d7c6b5a4f3e2d",
		MetaGenerator:    "WordPress 6.4.2",
		BodySnippet:      strings.Repeat("<div class=\"content\">Instytut Informatyki AGH - aktualnosci, ogloszenia, plan zajec. ", 4),
		ResponseTimeMs:   42,
		MedianResponseMs: 38,
		ResponseSamples:  6,
		SafePathHits: []domain.SafePathHit{
			{Path: "/robots.txt", StatusCode: 200, Snippet: "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php"},
			{Path: "/wp-login.php", StatusCode: 200, Title: "Log In &lsaquo; Wydzial &#8212; WordPress", LoginForm: true},
		},
	}
	if s.TLS {
		fp.TLS = &domain.TLSInfo{
			Version: "TLS 1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
			SubjectCN: h.IP, Issuer: "CN=AGH Internal CA,O=AGH,C=PL",
			SANs:      []string{h.IP, "www.lab.agh.edu.pl"},
			NotBefore: l0, NotAfter: l0.Add(398 * 24 * time.Hour), DaysToExpiry: 120,
			SHA256: "9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
			JARM:   "2ad2ad16d2ad2ad00042d42d00000069d641f34fe76acdc05c40262f8815e5",
		}
	}
	return fp
}

var l0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// observe returns run r's observations (only live hosts) and the merged nmap XML.
func (l *lab) observe(r int, scopeIPs []string) ([]domain.ObservedHost, string) {
	inScope := make(map[string]bool, len(scopeIPs))
	for _, ip := range scopeIPs {
		inScope[ip] = true
	}
	rng := rand.New(rand.NewSource(l.m.Seed*7777 + int64(r)))
	at := l.runTime(r)
	var obs []domain.ObservedHost
	var xml strings.Builder
	xml.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<nmaprun scanner="nmap" args="nmap -sV" start="1" version="7.94" xmloutputversion="1.05">` + "\n")
	for _, h := range l.hosts {
		if !inScope[h.IP] || r < h.Birth || (h.Death > 0 && r >= h.Death) {
			continue
		}
		if h.Flappy && rng.Float64() < 0.4 {
			continue
		}
		oh := domain.ObservedHost{IP: h.IP, Hostname: h.Hostname, OSGuess: h.OS, IsAlive: true, ObservedAt: at}
		fmt.Fprintf(&xml, `<host starttime="%d" endtime="%d"><status state="up" reason="syn-ack" reason_ttl="63"/><address addr="%s" addrtype="ipv4"/>`, at.Unix(), at.Unix()+40, h.IP)
		if h.Hostname != "" {
			fmt.Fprintf(&xml, `<hostnames><hostname name="%s" type="PTR"/></hostnames>`, h.Hostname)
		}
		xml.WriteString("<ports>")
		for i := range h.Services {
			s := &h.Services[i]
			if s.Closed {
				continue
			}
			osvc := domain.ObservedService{Port: s.Port, Protocol: "tcp", State: "open", ServiceName: s.Name,
				Product: s.Product, Version: s.Version, Banner: s.Banner}
			if s.HTTP {
				osvc.HTTP = httpFP(h, s)
			}
			oh.Services = append(oh.Services, osvc)
			fmt.Fprintf(&xml, `<port protocol="tcp" portid="%d"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="%s" product="%s" version="%s" method="probed" conf="10"><cpe>cpe:/a:vendor:%s:%s</cpe></service></port>`,
				s.Port, s.Name, s.Product, s.Version, strings.ToLower(strings.ReplaceAll(s.Product, " ", "_")), s.Version)
		}
		xml.WriteString(`</ports><times srtt="512" rttvar="300" to="100000"/></host>` + "\n")
		obs = append(obs, oh)
	}
	xml.WriteString(`<runstats><finished time="1" elapsed="600" exit="success"/></runstats></nmaprun>` + "\n")
	return obs, xml.String()
}

// chunks mimics scanner.ChunkTargets: 256-IP chunks with the command lines the engine logs.
func chunks(runID string, scopeIPs []string, obs []domain.ObservedHost) []domain.ScanChunk {
	alive := map[string]bool{}
	for _, o := range obs {
		alive[o.IP] = true
	}
	ports, _ := scanner.ParsePorts(scanner.AutoWidePorts)
	opts := scanner.DefaultNmapOptions()
	now := time.Now().UTC()
	var out []domain.ScanChunk
	for i := 0; i*256 < len(scopeIPs); i++ {
		end := min((i+1)*256, len(scopeIPs))
		tg := append([]string(nil), scopeIPs[i*256:end]...)
		var live []string
		for _, ip := range tg {
			if alive[ip] {
				live = append(live, ip)
			}
		}
		cmds := []string{
			scanner.FormatCommand("nmap", opts.BuildICMPArgs(tg, 250)),
			scanner.FormatCommand("nmap", opts.BuildSweepArgs(tg, ports, 250, true)),
		}
		if len(live) > 0 {
			cmds = append(cmds, scanner.FormatCommand("nmap", opts.BuildServiceArgs(live, ports, 250)))
		}
		out = append(out, domain.ScanChunk{
			ID: fmt.Sprintf("%s-chunk-%04d", runID, i), ScanRunID: runID, ChunkIndex: i, Targets: tg,
			IPCount: len(tg), Status: domain.ChunkStatusDone, ActiveHosts: len(live), Services: len(live) * 2,
			DurationMs: 41000, StartedAt: &now, FinishedAt: &now, NmapCommands: cmds, MaxRatePPS: 250, Worker: 1 + i%4,
		})
	}
	return out
}

// simulateRun drives one run the way LiveScanRunner does: create the run and its chunk
// ledger, update chunks as they finish, ingest through the pipeline, finish the run, then
// record the side documents a real run leaves behind (telemetry, DefectDojo push, audit).
func simulateRun(ctx context.Context, store db.Store, p *ingest.Pipeline, l *lab, profileID string, r int, chunkUpdates bool) error {
	l.evolve(r)
	label, scopeIPs := l.scope(r)
	obs, xml := l.observe(r, scopeIPs)
	at := l.runTime(r)
	run := &domain.ScanRun{
		ID: db.NewID(), ProfileID: profileID, Name: fmt.Sprintf("lab %s #%d", label, r+1), RunType: domain.ScanTypeActive,
		Status: domain.ScanStatusRunning, TotalIPs: len(scopeIPs), TriggeredBy: "scheduler", StartedAt: at,
	}
	cks := chunks(run.ID, scopeIPs, obs)
	run.TotalChunks = len(cks)
	if err := store.CreateScanRun(ctx, run); err != nil {
		return err
	}
	if chunkUpdates {
		pending := make([]domain.ScanChunk, len(cks))
		for i := range cks {
			pending[i] = cks[i]
			pending[i].Status, pending[i].NmapCommands = domain.ChunkStatusPending, nil
		}
		_ = store.SaveScanChunks(ctx, run.ID, pending)
		for i := range cks {
			pending[i] = cks[i]
			_ = store.SaveScanChunks(ctx, run.ID, pending)
		}
	} else {
		_ = store.SaveScanChunks(ctx, run.ID, cks)
	}
	run.CompletedChunks, run.ScannedIPs, run.ActiveHosts = len(cks), len(scopeIPs), len(obs)
	_ = store.UpdateScanRun(ctx, run)
	if _, err := p.ProcessObservations(ctx, ingest.IngestRequest{
		ScanRunID: run.ID, ProfileID: profileID, RunType: domain.ScanTypeActive, ScanName: run.Name,
		TriggeredBy: run.TriggeredBy, RawNmapXML: xml, Observations: obs, ScopeIPs: scopeIPs,
		MarkMissingHosts: true, MissingThreshold: 2, GracePeriodHours: 24,
	}); err != nil {
		return err
	}
	saved, err := store.GetScanRun(ctx, run.ID)
	if err != nil {
		return err
	}
	fin := at.Add(25 * time.Minute)
	saved.Status, saved.FinishedAt, saved.DurationMs = domain.ScanStatusCompleted, &fin, 25*60*1000
	saved.RawNmapXML = ""
	_ = store.UpdateScanRun(ctx, saved)

	if ss, ok := store.(db.SettingsStore); ok {
		t := domain.ScanTelemetry{ConfiguredPPS: 500, ConfiguredHTTPRPS: 25, NmapPeakPPS: 480, HTTPRateRPS: 18, HTTPInitialRPS: 25, Timeouts: 12}
		for i := 0; i < 50; i++ {
			t.Throttles = append(t.Throttles, domain.ThrottleEntry{At: at, Host: obsIP(obs, i), Reason: "timeouts", OldRate: 25, NewRate: 18, Errors: 3})
			t.ThrottleCount++
		}
		for i := 0; i < 6; i++ {
			t.WindowEvents = append(t.WindowEvents, domain.WindowEntry{At: at, Kind: "paused", NextOpen: at.Add(time.Hour).Format(time.RFC3339)})
		}
		_ = ss.SaveSetting(ctx, "run_telemetry:"+run.ID, t)
	}
	_ = store.AddDefectDojoExport(ctx, &domain.DefectDojoExport{ExportType: "nmap_xml", SourceID: run.ID, Title: "Nmap Scan (auto): " + run.Name,
		Status: "success", ExternalURL: "https://dojo.example/test/42", ExportedBy: "auto-push", CreatedAt: fin})
	_ = store.AddDefectDojoExport(ctx, &domain.DefectDojoExport{ExportType: "finding", SourceID: run.ID, Title: "Dzięcioł changes: " + run.Name,
		Status: "success", ExternalURL: "https://dojo.example/test/43", ExportedBy: "auto-push", CreatedAt: fin})
	_ = store.AddAuditLog(ctx, &domain.AuditLog{Username: "admin", RoleSlug: "admin", Action: "POST /api/v1/scans", Resource: "scans:write",
		Status: "success", IPAddress: "10.0.0.5", Details: map[string]any{"method": "POST", "path": "/api/v1/scans"}, CreatedAt: at})
	return nil
}

func obsIP(obs []domain.ObservedHost, i int) string {
	if len(obs) == 0 {
		return ""
	}
	return obs[i%len(obs)].IP
}

// ---------- measurement ----------

type sample struct {
	peakHeapAlloc atomic.Uint64
	peakHeapInuse atomic.Uint64
	peakSys       atomic.Uint64
	stop          chan struct{}
	done          chan struct{}
}

func startSampler() *sample {
	s := &sample{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			bump(&s.peakHeapAlloc, ms.HeapAlloc)
			bump(&s.peakHeapInuse, ms.HeapInuse)
			bump(&s.peakSys, ms.Sys-ms.HeapReleased)
			select {
			case <-s.stop:
				return
			case <-t.C:
			}
		}
	}()
	return s
}

func (s *sample) finish() {
	close(s.stop)
	<-s.done
}

func bump(a *atomic.Uint64, v uint64) {
	for {
		cur := a.Load()
		if v <= cur || a.CompareAndSwap(cur, v) {
			return
		}
	}
}

func maxRSS() uint64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return uint64(ru.Maxrss) // bytes
	}
	return uint64(ru.Maxrss) * 1024 // kilobytes on Linux
}

func mb(v uint64) string { return fmt.Sprintf("%.1f MB", float64(v)/(1<<20)) }

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func openStore(dir string, opts db.FileStoreOptions) (*db.FileStore, *crypto.Vault, error) {
	vault, err := crypto.NewVault(benchKey)
	if err != nil {
		return nil, nil, err
	}
	fs, err := db.OpenFileStore(filepath.Join(dir, storeFile), vault, opts)
	return fs, vault, err
}

func readMeta(dir string) (meta, error) {
	var m meta
	raw, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return m, fmt.Errorf("no %s in %s (run `storebench gen` first): %w", metaFile, dir, err)
	}
	return m, json.Unmarshal(raw, &m)
}

func writeHeapProfile(path string) error {
	if path == "" {
		return nil
	}
	runtime.GC()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pprof.Lookup("heap").WriteTo(f, 0)
}

func heapNow() runtime.MemStats {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms
}

// ---------- subcommands ----------

func cmdGen(dir string, m meta) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, storeFile))
	m.Base = time.Now().UTC().Truncate(time.Hour).Add(-time.Duration(m.Runs+1) * m.Every)
	raw, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, metaFile), raw, 0o600); err != nil {
		return err
	}
	// Long debounce: generation is not measured, one flush at the end is enough.
	fs, _, err := openStore(dir, db.FileStoreOptions{Debounce: time.Hour, MaxDelay: time.Hour, Interval: time.Hour, Retention: retention})
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := db.SeedDefaults(ctx, fs, true); err != nil {
		return err
	}
	prof := &domain.ScanProfile{Name: "Lab /18", Targets: []string{"10.66.0.0/18"}, AllowedPorts: "auto", MaxRatePPS: 500, Concurrency: 32}
	if err := fs.CreateProfile(ctx, prof); err != nil {
		return err
	}
	p := newPipeline(fs)
	l := newLab(m)
	t0 := time.Now()
	for r := 0; r < m.Runs; r++ {
		if err := simulateRun(ctx, fs, p, l, prof.ID, r, false); err != nil {
			return fmt.Errorf("run %d: %w", r, err)
		}
		if (r+1)%5 == 0 || r == m.Runs-1 {
			log.Printf("run %d/%d done (%s)", r+1, m.Runs, time.Since(t0).Round(time.Second))
		}
	}
	fs.Close()
	fmt.Printf("generated %d runs over %d hosts in %s: %s = %s\n", m.Runs, m.Hosts, time.Since(t0).Round(time.Second),
		storeFile, mb(uint64(fileSize(filepath.Join(dir, storeFile)))))
	return nil
}

type result struct {
	Phase           string  `json:"phase"`
	FileBefore      int64   `json:"file_before"`
	FileAfter       int64   `json:"file_after"`
	HeapAfter       uint64  `json:"heap_after"`
	PeakHeapAlloc   uint64  `json:"peak_heap_alloc"`
	PeakHeapInuse   uint64  `json:"peak_heap_inuse"`
	PeakSys         uint64  `json:"peak_sys"`
	MaxRSS          uint64  `json:"max_rss"`
	Seconds         float64 `json:"seconds"`
	TotalAllocBytes uint64  `json:"total_alloc"`
}

func printResult(r result, asJSON bool) {
	if asJSON {
		raw, _ := json.Marshal(r)
		fmt.Println(string(raw))
		return
	}
	fmt.Printf("%s: file %s -> %s, heap after %s, peak heap alloc %s, peak heap inuse %s, peak sys %s, max RSS %s, total alloc %s, %.1fs\n",
		r.Phase, mb(uint64(r.FileBefore)), mb(uint64(r.FileAfter)), mb(r.HeapAfter), mb(r.PeakHeapAlloc), mb(r.PeakHeapInuse),
		mb(r.PeakSys), mb(r.MaxRSS), mb(r.TotalAllocBytes), r.Seconds)
}

func cmdLoad(dir, heapProfile string, asJSON bool) error {
	path := filepath.Join(dir, storeFile)
	before := fileSize(path)
	s := startSampler()
	t0 := time.Now()
	fs, _, err := openStore(dir, db.FileStoreOptions{Retention: retention})
	if err != nil {
		return err
	}
	elapsed := time.Since(t0)
	ms := heapNow()
	s.finish()
	if err := writeHeapProfile(heapProfile); err != nil {
		return err
	}
	fs.Close()
	printResult(result{Phase: "load", FileBefore: before, FileAfter: fileSize(path), HeapAfter: ms.HeapAlloc,
		PeakHeapAlloc: s.peakHeapAlloc.Load(), PeakHeapInuse: s.peakHeapInuse.Load(), PeakSys: s.peakSys.Load(),
		MaxRSS: maxRSS(), Seconds: elapsed.Seconds(), TotalAllocBytes: ms.TotalAlloc}, asJSON)
	return nil
}

func cmdIngest(dir, heapProfile string, asJSON bool) error {
	m, err := readMeta(dir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, storeFile)
	before := fileSize(path)
	fs, _, err := openStore(dir, db.FileStoreOptions{Retention: retention}) // default debounce: flushes during the run like serve
	if err != nil {
		return err
	}
	ctx := context.Background()
	profiles, _ := fs.ListProfiles(ctx)
	profileID := ""
	for _, p := range profiles {
		if p.Name == "Lab /18" {
			profileID = p.ID
		}
	}
	l := newLab(m)
	for r := 0; r < m.Runs; r++ {
		l.evolve(r) // replay the drift so the next run continues the same lab
	}
	p := newPipeline(fs)
	runtime.GC()
	var ms0 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	s := startSampler()
	t0 := time.Now()
	r := (m.Runs/m.FullEvery + 1) * m.FullEvery // next full /18 run
	if err := simulateRun(ctx, fs, p, l, profileID, r, true); err != nil {
		return err
	}
	if err := fs.Flush(); err != nil {
		return err
	}
	elapsed := time.Since(t0)
	s.finish()
	ms := heapNow()
	if err := writeHeapProfile(heapProfile); err != nil {
		return err
	}
	fs.Close()
	printResult(result{Phase: "ingest", FileBefore: before, FileAfter: fileSize(path), HeapAfter: ms.HeapAlloc,
		PeakHeapAlloc: s.peakHeapAlloc.Load(), PeakHeapInuse: s.peakHeapInuse.Load(), PeakSys: s.peakSys.Load(),
		MaxRSS: maxRSS(), Seconds: elapsed.Seconds(), TotalAllocBytes: ms.TotalAlloc - ms0.TotalAlloc}, asJSON)
	return nil
}

func cmdStats(dir string) error {
	path := filepath.Join(dir, storeFile)
	fs, _, err := openStore(dir, db.FileStoreOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer fs.Close()
	stats := fs.CollectionStats()
	var total int64
	for _, s := range stats {
		if !s.Part {
			total += s.Bytes
		}
	}
	fmt.Printf("%s: %s on disk, %s of JSON\n", path, mb(uint64(fileSize(path))), mb(uint64(total)))
	fmt.Printf("%-34s %10s %12s %7s\n", "collection", "items", "bytes", "share")
	for _, s := range stats {
		name := s.Name
		if s.Part {
			name = "  " + name
		}
		fmt.Printf("%-34s %10d %12s %6.1f%%\n", name, s.Items, mb(uint64(s.Bytes)), 100*float64(s.Bytes)/float64(max(total, 1)))
	}
	return nil
}
