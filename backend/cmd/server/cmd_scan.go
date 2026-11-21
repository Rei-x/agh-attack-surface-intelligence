package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/ingest"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/localdata"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

const scanUsage = `Usage: dzieciol scan <targets...> [flags]
       dzieciol scan -f targets.txt [flags]

Targets: IPs, CIDRs (10.0.0.0/24), ranges (10.0.0.1-10.0.0.50) or hostnames.
Results are stored in the local encrypted store and visible in 'dzieciol serve'.
Stored target exclusions (configured in the web UI) are honoured unless --ignore-exclusions.`

const defaultCLIPorts = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8000,8080,8443,9000,9200"

func cmdScan(args []string) error {
	fs := newFlagSet("scan", scanUsage)
	var ports string
	fs.StringVar(&ports, "ports", defaultCLIPorts, "ports to scan (e.g. 22,80,443,8000-8100)")
	fs.StringVar(&ports, "p", defaultCLIPorts, "shorthand for --ports")
	file := fs.String("f", "", "read targets from file (one per line, # comments)")
	rate := fs.Int("rate", 500, "max probe rate (packets/connections per second)")
	httpRPS := fs.Int("http-rps", 25, "max HTTP fingerprint requests per second per host")
	concurrency := fs.Int("concurrency", 32, "parallel host workers")
	chunkSec := fs.Int("chunk-sec", 10, "target duration of one scan chunk (checkpoint granularity)")
	profileRef := fs.String("profile", "", "use a stored scan profile (name or ID) for defaults/targets")
	name := fs.String("name", "", "scan run name (default: CLI <targets> <time>)")
	noNmap := fs.Bool("no-nmap", false, "force the pure-Go scanner even if nmap is installed")
	ignoreExcl := fs.Bool("ignore-exclusions", false, "do not apply stored target exclusions (e.g. the default 127.0.0.0/8)")
	noHTTP := fs.Bool("no-http", false, "skip HTTP/TLS fingerprinting")
	jsonOut := fs.Bool("json", false, "print the JSON report to stdout instead of tables")
	outFile := fs.String("o", "", "also write the JSON report to this file")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.dzieciol)")
	verbose := fs.Bool("verbose", false, "show internal log output")
	targets, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	setFlags := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	if *file != "" {
		fileTargets, err := readTargetsFile(*file)
		if err != nil {
			return err
		}
		targets = append(targets, fileTargets...)
	}
	if len(targets) == 0 && *profileRef == "" {
		fs.Usage()
		return errors.New("no targets given (pass IPs/CIDRs/ranges, -f file, or --profile)")
	}

	quietLogs(*verbose)
	status := os.Stderr
	si := detectScanner()
	if *noNmap {
		si.NmapPath = ""
		si.ForcedGo = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rt, err := openRuntime(context.Background(), runtimeOptions{
		DataDir: *dataDir, Command: "scan", Seed: true, SeedDemo: seedDemoDefault(),
	})
	if err != nil {
		var le *localdata.ErrLocked
		if errors.As(err, &le) {
			return fmt.Errorf("%w\n  The local store is single-writer. Either stop `dzieciol serve` and re-run this command,\n"+
				"  or start the scan from the web UI (Scans page) / API: POST /api/v1/scans", err)
		}
		return err
	}
	defer rt.Close()
	store := rt.Store
	bg := context.Background()

	// Build the profile: stored profile (optional) overridden by explicit flags.
	var stored *domain.ScanProfile
	if *profileRef != "" {
		if stored, err = findProfile(bg, store, *profileRef); err != nil {
			return err
		}
	}
	profile := buildCLIProfile(stored, cliProfileFlags{
		Ports: ports, Rate: *rate, HTTPRPS: *httpRPS, Concurrency: *concurrency,
		ChunkSec: *chunkSec, NoHTTP: *noHTTP,
	}, setFlags)
	if len(targets) > 0 {
		profile.Targets = targets
	}

	var exclusions []domain.TargetExclusion
	if !*ignoreExcl {
		exclusions, _ = store.ListExclusions(bg)
	}

	runRunner := NewLiveScanRunner(store, nil, nil)
	unstable := runRunner.collectTrackedHostIPs(bg)
	engine := scanner.NewEngine(scanner.EngineConfig{UseNmap: si.HasNmap(), UnstableHosts: unstable})

	runID := db.NewID()
	runName := strings.TrimSpace(*name)
	if runName == "" {
		runName = "CLI " + summarizeTargets(profile.Targets) + " " + time.Now().Format("2006-01-02 15:04")
	}

	prepared, resolution, err := engine.PrepareRun(bg, runID, profile, exclusions)
	if err == nil && prepared.TotalIPs == 0 {
		err = errors.New("no targets left to scan")
	}
	if err != nil {
		if !*ignoreExcl && len(exclusions) > 0 {
			if _, r2, e2 := engine.PrepareRun(bg, runID, profile, nil); e2 == nil && r2 != nil && len(r2.IPs) > 0 {
				var ex []string
				for _, e := range exclusions {
					ex = append(ex, fmt.Sprintf("%s (%s)", e.Value, e.Reason))
				}
				return fmt.Errorf("all targets are covered by stored exclusions: %s\n  re-run with --ignore-exclusions to scan them anyway (e.g. for a local test on 127.0.0.1)", strings.Join(ex, ", "))
			}
		}
		return fmt.Errorf("prepare scan: %w", err)
	}

	run := prepared
	run.Name = runName
	run.TriggeredBy = "cli"
	run.Status = domain.ScanStatusRunning
	if err := store.CreateScanRun(bg, run); err != nil {
		return err
	}
	_ = store.SaveScanChunks(bg, run.ID, run.Chunks)

	printPreflight(status, si)
	excluded := 0
	if resolution != nil {
		excluded = resolution.ExcludedCount
	}
	fmt.Fprintf(status, "scan:    %d target IPs, ports %s, rate %d pps, %d workers, %d chunks", run.TotalIPs, compactPorts(profile.AllowedPorts), profile.MaxRatePPS, profile.Concurrency, run.TotalChunks)
	if excluded > 0 {
		fmt.Fprintf(status, ", %d IPs excluded", excluded)
	}
	fmt.Fprintf(status, "\nstore:   %s\n\n", rt.storeDescription())

	prog := newProgress(status, run.TotalIPs, run.TotalChunks)
	prog.start()
	started := time.Now()
	res, execErr := engine.Execute(ctx, run, profile, resolution, scanner.RunCallbacks{
		OnEvent: func(ev domain.LiveEvent) {
			if ev.Type == "scan.chunk" {
				if st, _ := ev.Payload["status"].(string); st == domain.ChunkStatusRunning {
					prog.chunkStarted()
				}
			}
		},
		OnHostObserved: func(obs domain.ObservedHost) {
			if obs.IsAlive {
				prog.hostAlive(obs)
			}
		},
		OnCheckpoint: func(cp *domain.ScanRun) {
			prog.update(cp.ScannedIPs, cp.ActiveHosts, cp.ServicesFound, cp.CompletedChunks)
			_ = store.UpdateScanRun(bg, cp)
			_ = store.SaveScanChunks(bg, cp.ID, cp.Chunks)
		},
	})
	prog.stop()
	elapsed := time.Since(started)

	interrupted := execErr != nil && errors.Is(execErr, context.Canceled)
	if execErr != nil && !interrupted {
		now := time.Now().UTC()
		run.Status = domain.ScanStatusFailed
		run.FinishedAt = &now
		_ = store.UpdateScanRun(bg, run)
		return fmt.Errorf("scan failed: %w", execErr)
	}
	if interrupted {
		now := time.Now().UTC()
		run.Status = domain.ScanStatusStopped
		run.FinishedAt = &now
		_ = store.UpdateScanRun(bg, run)
		partial := 0
		if res != nil {
			partial = len(res.ObservedHosts)
		}
		fmt.Fprintf(status, "interrupted - saving %d partial host results\n", partial)
	}

	// Find previous completed run (before ingest) for the summary header.
	prevRun := previousCompletedRun(bg, store, run.ID)

	pipeline := rt.newPipeline(nil)
	var ingestRes *ingest.IngestResult
	if res != nil && (len(res.ObservedHosts) > 0 || res.RawNmapXML != "") {
		var scope []string
		if resolution != nil {
			scope = resolution.IPs
		}
		ingestRes, err = pipeline.ProcessObservations(bg, ingest.IngestRequest{
			ScanRunID:        run.ID,
			RunType:          domain.ScanTypeActive,
			ScanName:         run.Name,
			TriggeredBy:      "cli",
			RawNmapXML:       res.RawNmapXML,
			Observations:     res.ObservedHosts,
			ScopeIPs:         scope,
			MarkMissingHosts: !interrupted,
			MissingThreshold: profile.MissingThreshold,
			GracePeriodHours: profile.GracePeriodHours,
		})
		if err != nil {
			return fmt.Errorf("ingest results: %w", err)
		}
	} else {
		// Nothing alive: still record a snapshot so diffs work.
		hosts, _, _ := store.ListHosts(bg, db.HostFilter{})
		_ = store.SaveScanSnapshot(bg, run.ID, hosts)
	}
	if saved, err := store.GetScanRun(bg, run.ID); err == nil {
		run = saved
	}

	report := buildScanReport(bg, store, run, res, ingestRes, prevRun, si, elapsed)
	if rt.FileStore != nil {
		if err := rt.FileStore.Flush(); err != nil {
			return fmt.Errorf("save store: %w", err)
		}
	}

	if *outFile != "" {
		if err := writeJSONFile(*outFile, report); err != nil {
			return err
		}
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printScanReport(os.Stdout, report)
	}
	if *outFile != "" {
		fmt.Fprintf(status, "report written to %s\n", *outFile)
	}
	if interrupted {
		return errors.New("scan interrupted")
	}
	return nil
}

// cliProfileFlags are the `dzieciol scan` flags that map onto ScanProfile fields.
type cliProfileFlags struct {
	Ports       string
	Rate        int
	HTTPRPS     int
	Concurrency int
	ChunkSec    int
	NoHTTP      bool
}

// buildCLIProfile returns the profile for a terminal scan: CLI defaults, or the stored
// profile with only the explicitly set flags (set) overriding it.
func buildCLIProfile(stored *domain.ScanProfile, f cliProfileFlags, set map[string]bool) domain.ScanProfile {
	if stored == nil {
		return domain.ScanProfile{
			Name:                  "CLI",
			AllowedPorts:          f.Ports,
			MaxRatePPS:            f.Rate,
			HTTPRPS:               f.HTTPRPS,
			Concurrency:           f.Concurrency,
			ChunkTargetSec:        f.ChunkSec,
			Timezone:              "Europe/Warsaw",
			MissingThreshold:      2,
			GracePeriodHours:      24,
			RetryUnstableCount:    2,
			EnableHTTPFingerprint: !f.NoHTTP,
			UserAgent:             "Dzieciol-CBI-AGH/" + appVersion(),
			Enabled:               true,
		}
	}
	base := *stored
	if set["ports"] || set["p"] {
		base.AllowedPorts = f.Ports
	}
	if set["rate"] {
		base.MaxRatePPS = f.Rate
	}
	if set["http-rps"] {
		base.HTTPRPS = f.HTTPRPS
	}
	if set["concurrency"] {
		base.Concurrency = f.Concurrency
	}
	if set["chunk-sec"] {
		base.ChunkTargetSec = f.ChunkSec
	}
	if f.NoHTTP {
		base.EnableHTTPFingerprint = false
	}
	// A terminal scan runs now; the profile's time window is not enforced here.
	base.WindowEnabled = false
	return base
}

func readTargetsFile(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == ';' }) {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, tok)
			}
		}
	}
	return out, sc.Err()
}

func findProfile(ctx context.Context, store db.Store, ref string) (*domain.ScanProfile, error) {
	profiles, err := store.ListProfiles(ctx)
	if err != nil {
		return nil, err
	}
	ref = strings.TrimSpace(ref)
	var matches []domain.ScanProfile
	for _, p := range profiles {
		if p.ID == ref || strings.EqualFold(p.Name, ref) {
			return &p, nil
		}
		if strings.Contains(strings.ToLower(p.Name), strings.ToLower(ref)) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	var names []string
	for _, p := range profiles {
		names = append(names, fmt.Sprintf("%q", p.Name))
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("profile %q is ambiguous; available: %s", ref, strings.Join(names, ", "))
	}
	return nil, fmt.Errorf("profile %q not found; available: %s", ref, strings.Join(names, ", "))
}

func previousCompletedRun(ctx context.Context, store db.Store, excludeID string) *domain.ScanRun {
	runs, err := store.ListScanRuns(ctx, 50)
	if err != nil {
		return nil
	}
	for _, r := range runs {
		if r.ID != excludeID && r.Status == domain.ScanStatusCompleted {
			rc := r
			return &rc
		}
	}
	return nil
}

func summarizeTargets(t []string) string {
	if len(t) == 0 {
		return ""
	}
	if len(t) <= 2 {
		return strings.Join(t, ",")
	}
	return fmt.Sprintf("%s,%s +%d", t[0], t[1], len(t)-2)
}

func compactPorts(p string) string {
	if len(p) > 40 {
		return p[:37] + "..."
	}
	return p
}

func writeJSONFile(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// ---------------------------------------------------------------------------
// Live progress line
// ---------------------------------------------------------------------------

type progress struct {
	w           io.Writer
	tty         bool
	totalIPs    int
	totalChunks int

	mu        sync.Mutex
	scanned   int
	alive     int
	services  int
	chunks    int
	running   bool
	startedAt time.Time
	lastHost  string

	stopCh chan struct{}
	doneCh chan struct{}
}

func newProgress(w *os.File, totalIPs, totalChunks int) *progress {
	tty := false
	if fi, err := w.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		tty = true
	}
	return &progress{w: w, tty: tty, totalIPs: totalIPs, totalChunks: totalChunks,
		stopCh: make(chan struct{}), doneCh: make(chan struct{})}
}

func (p *progress) start() {
	p.startedAt = time.Now()
	go func() {
		defer close(p.doneCh)
		interval := 200 * time.Millisecond
		if !p.tty {
			interval = 5 * time.Second
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		frame := 0
		for {
			select {
			case <-p.stopCh:
				p.render(frame, true)
				return
			case <-t.C:
				frame++
				p.render(frame, false)
			}
		}
	}()
}

func (p *progress) stop() {
	close(p.stopCh)
	<-p.doneCh
}

func (p *progress) chunkStarted() {
	p.mu.Lock()
	p.running = true
	p.mu.Unlock()
}

func (p *progress) hostAlive(obs domain.ObservedHost) {
	p.mu.Lock()
	p.lastHost = fmt.Sprintf("%s (%d svc)", obs.IP, len(obs.Services))
	p.mu.Unlock()
}

func (p *progress) update(scanned, alive, services, chunks int) {
	p.mu.Lock()
	p.scanned, p.alive, p.services, p.chunks = scanned, alive, services, chunks
	p.mu.Unlock()
}

func (p *progress) render(frame int, final bool) {
	p.mu.Lock()
	scanned, alive, services, chunks, last := p.scanned, p.alive, p.services, p.chunks, p.lastHost
	p.mu.Unlock()
	elapsed := time.Since(p.startedAt)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(scanned) / elapsed.Seconds()
	}
	eta := "--:--"
	if rate > 0 && scanned < p.totalIPs {
		eta = fmtDuration(time.Duration(float64(p.totalIPs-scanned)/rate) * time.Second)
	} else if scanned >= p.totalIPs {
		eta = "0:00"
	}
	pct := 0.0
	if p.totalIPs > 0 {
		pct = float64(scanned) / float64(p.totalIPs)
	}
	const width = 24
	filled := int(pct * width)
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	spin := `|/-\`[frame%4]
	if final {
		spin = ' '
	}
	line := fmt.Sprintf("%c [%s] %3.0f%%  hosts %d/%d  %s hosts/s  ETA %s  live %d  services %d  chunk %d/%d  elapsed %s",
		spin, bar, pct*100, scanned, p.totalIPs, fmtRate(rate), eta, alive, services, chunks, p.totalChunks, fmtDuration(elapsed))
	if last != "" && !final {
		line += "  last " + last
	}
	if p.tty {
		fmt.Fprintf(p.w, "\r\033[K%s", line)
		if final {
			fmt.Fprint(p.w, "\n\n")
		}
	} else {
		fmt.Fprintln(p.w, strings.TrimSpace(line))
	}
}

func fmtRate(r float64) string {
	switch {
	case r == 0:
		return "0"
	case r < 1:
		return fmt.Sprintf("%.2f", r)
	case r < 100:
		return fmt.Sprintf("%.1f", r)
	}
	return fmt.Sprintf("%.0f", r)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

type scanFinding struct {
	Score    int      `json:"score"`
	HostIP   string   `json:"host_ip"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Service  string   `json:"service"`
	Product  string   `json:"product,omitempty"`
	Title    string   `json:"title,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Reasons  []string `json:"reasons,omitempty"`
}

type scanChangeSummary struct {
	PreviousRunID   string `json:"previous_run_id,omitempty"`
	PreviousRunName string `json:"previous_run_name,omitempty"`
	NewHosts        int    `json:"new_hosts"`
	GoneHosts       int    `json:"gone_hosts"`
	NewServices     int    `json:"new_services"`
	ClosedServices  int    `json:"closed_services"`
	Changed         int    `json:"changed"`
}

type scanReport struct {
	Version     string               `json:"dzieciol_version"`
	ScanRun     *domain.ScanRun      `json:"scan_run"`
	Engine      string               `json:"engine"`
	DurationSec float64              `json:"duration_sec"`
	HostsPerSec float64              `json:"hosts_per_sec"`
	TargetIPs   int                  `json:"target_ips"`
	LiveHosts   int                  `json:"live_hosts"`
	Services    int                  `json:"services"`
	Hosts       []domain.Host        `json:"hosts"`
	Findings    []scanFinding        `json:"top_findings"`
	Changes     scanChangeSummary    `json:"changes_summary"`
	ChangeList  []domain.ChangeEvent `json:"changes"`
}

func buildScanReport(ctx context.Context, store db.Store, run *domain.ScanRun, res *scanner.RunResult, ing *ingest.IngestResult, prev *domain.ScanRun, si scannerInfo, elapsed time.Duration) *scanReport {
	rep := &scanReport{
		Version:     appVersion(),
		ScanRun:     run,
		Engine:      si.Engine(),
		DurationSec: elapsed.Seconds(),
		TargetIPs:   run.TotalIPs,
		Hosts:       []domain.Host{},
		Findings:    []scanFinding{},
		ChangeList:  []domain.ChangeEvent{},
	}
	if elapsed > 0 {
		rep.HostsPerSec = float64(run.ScannedIPs) / elapsed.Seconds()
	}
	if prev != nil {
		rep.Changes.PreviousRunID = prev.ID
		rep.Changes.PreviousRunName = prev.Name
	}
	if res != nil {
		seen := map[string]bool{}
		for _, obs := range res.ObservedHosts {
			if !obs.IsAlive || seen[obs.IP] {
				continue
			}
			seen[obs.IP] = true
			h, err := store.GetHostByIP(ctx, obs.IP)
			if err != nil {
				continue
			}
			rep.Hosts = append(rep.Hosts, *h)
			rep.Services += len(h.Services)
			for _, s := range h.Services {
				f := scanFinding{
					Score: s.Interestingness, HostIP: h.IP, Port: s.Port, Protocol: s.Protocol,
					Service: s.ServiceName, Product: strings.TrimSpace(s.Product + " " + s.Version),
				}
				if s.HTTP != nil {
					f.Title = s.HTTP.Title
				}
				if s.IsAdminPanel {
					f.Tags = append(f.Tags, "admin-panel")
				}
				if s.IsStagingEnv {
					f.Tags = append(f.Tags, "staging")
				}
				if s.IsIoT {
					f.Tags = append(f.Tags, "iot")
				}
				for _, t := range s.Technologies {
					label := t.Name
					if t.Version != "" {
						label += " " + t.Version
					}
					f.Tags = append(f.Tags, label)
				}
				factors := append([]domain.InterestingnessFactor(nil), s.InterestingFactors...)
				sort.SliceStable(factors, func(i, j int) bool { return factors[i].Points > factors[j].Points })
				for i, fc := range factors {
					if i >= 3 {
						break
					}
					f.Reasons = append(f.Reasons, fc.Reason)
				}
				rep.Findings = append(rep.Findings, f)
			}
		}
		sort.Slice(rep.Hosts, func(i, j int) bool { return ipLess(rep.Hosts[i].IP, rep.Hosts[j].IP) })
		sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Score > rep.Findings[j].Score })
		if len(rep.Findings) > 10 {
			rep.Findings = rep.Findings[:10]
		}
	}
	rep.LiveHosts = len(rep.Hosts)
	if ing != nil {
		rep.ChangeList = append(rep.ChangeList, ing.Changes...)
		sort.SliceStable(rep.ChangeList, func(i, j int) bool {
			return severityRank(rep.ChangeList[i].Severity) > severityRank(rep.ChangeList[j].Severity)
		})
		for _, c := range ing.Changes {
			switch changeCategory(c.EventType) {
			case "new_host":
				rep.Changes.NewHosts++
			case "gone_host":
				rep.Changes.GoneHosts++
			case "new_service":
				rep.Changes.NewServices++
			case "closed_service":
				rep.Changes.ClosedServices++
			default:
				rep.Changes.Changed++
			}
		}
	}
	return rep
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func changeCategory(t string) string {
	switch t {
	case "NEW_HOST", "HOST_REACTIVATED":
		return "new_host"
	case "HOST_MISSING", "HOST_INACTIVE":
		return "gone_host"
	case "NEW_SERVICE", "ADMIN_PANEL_EXPOSED":
		return "new_service"
	case "SERVICE_CLOSED":
		return "closed_service"
	}
	return "changed"
}

func changeSymbol(t string) string {
	switch changeCategory(t) {
	case "new_host", "new_service":
		return "+"
	case "gone_host", "closed_service":
		return "-"
	}
	return "~"
}

func printScanReport(w io.Writer, rep *scanReport) {
	run := rep.ScanRun
	fmt.Fprintf(w, "Scan %q %s in %s  (run %s)\n", run.Name, strings.ToLower(run.Status), fmtDuration(time.Duration(rep.DurationSec*float64(time.Second))), run.ID)
	fmt.Fprintf(w, "  targets %d   live hosts %d   services %d   %s hosts/s   engine %s\n\n",
		rep.TargetIPs, rep.LiveHosts, rep.Services, fmtRate(rep.HostsPerSec), rep.Engine)

	if len(rep.Hosts) == 0 {
		fmt.Fprintln(w, "No live hosts found.")
	} else {
		fmt.Fprintln(w, "LIVE HOSTS")
		tw := newTable(w)
		fmt.Fprintln(tw, "  IP\tHOSTNAME\tSTATE\tSCORE\tOPEN PORTS")
		for _, h := range rep.Hosts {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%s\n", h.IP, dash(h.Hostname), h.LifecycleState, h.Interestingness, portList(h.Services, 8))
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	if len(rep.Findings) > 0 {
		fmt.Fprintln(w, "TOP FINDINGS")
		tw := newTable(w)
		fmt.Fprintln(tw, "  SCORE\tENDPOINT\tSERVICE\tDETAILS")
		for _, f := range rep.Findings {
			details := []string{}
			if f.Title != "" {
				details = append(details, fmt.Sprintf("%q", truncate(f.Title, 40)))
			}
			if len(f.Tags) > 0 {
				details = append(details, "["+strings.Join(f.Tags, ", ")+"]")
			}
			if len(f.Reasons) > 0 {
				details = append(details, strings.Join(f.Reasons, "; "))
			}
			svc := f.Service
			if f.Product != "" {
				svc += " (" + truncate(f.Product, 30) + ")"
			}
			fmt.Fprintf(tw, "  %d\t%s:%d/%s\t%s\t%s\n", f.Score, f.HostIP, f.Port, f.Protocol, svc, truncate(strings.Join(details, " "), 90))
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	c := rep.Changes
	if c.PreviousRunID == "" {
		fmt.Fprintln(w, "CHANGES: first scan in this store - baseline recorded.")
	} else {
		fmt.Fprintf(w, "CHANGES vs previous run %q\n", c.PreviousRunName)
	}
	fmt.Fprintf(w, "  +%d new hosts   -%d gone hosts   +%d new services   -%d closed services   ~%d changed\n",
		c.NewHosts, c.GoneHosts, c.NewServices, c.ClosedServices, c.Changed)
	if c.PreviousRunID != "" {
		limit := 15
		for i, ev := range rep.ChangeList {
			if i >= limit {
				fmt.Fprintf(w, "  ... %d more (dzieciol diff, or the Changes view in the UI)\n", len(rep.ChangeList)-limit)
				break
			}
			fmt.Fprintf(w, "  %s %-20s %s\n", changeSymbol(ev.EventType), ev.EventType, truncate(ev.Summary, 100))
		}
	}
	fmt.Fprintf(w, "\nResults saved. View them with `dzieciol serve`, compare with `dzieciol diff`, export with `dzieciol export`.\n")
}
