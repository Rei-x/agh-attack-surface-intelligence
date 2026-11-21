package scanner

import (
	"context"
	"hash/fnv"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/fingerprint"
)

// RunCallbacks delivers live progress, chunk updates, observations, and checkpoints.
type RunCallbacks struct {
	OnEvent        func(domain.LiveEvent)
	OnChunkUpdate  func(domain.ScanChunk)
	OnHostObserved func(domain.ObservedHost)
	OnCheckpoint   func(*domain.ScanRun)
}

// RunResult holds the final or checkpointed scan outputs from Engine.Execute.
type RunResult struct {
	ScanRun        *domain.ScanRun       `json:"scan_run"`
	ObservedHosts  []domain.ObservedHost `json:"observed_hosts"`
	RawNmapXML     string                `json:"raw_nmap_xml,omitempty"`
	GovernorStats  GovernorStats         `json:"governor_stats"`
	PausedByWindow bool                  `json:"paused_by_window"`
	// ScannedIPs lists the IPs of chunks completed during THIS Execute call (one window
	// segment). Callers must use it (not the full scope) when marking hosts missing,
	// otherwise hosts scanned in an earlier window would be wrongly flagged as gone.
	ScannedIPs []string `json:"-"`
	// ChunkWorkers is the number of concurrent chunk workers used in this segment.
	ChunkWorkers int `json:"chunk_workers"`
	// PerWorkerRatePPS is the --max-rate given to each concurrent nmap process.
	PerWorkerRatePPS int `json:"per_worker_rate_pps"`
	// StageTimings breaks down where scanner time went in this segment.
	StageTimings StageTimings `json:"stage_timings"`
}

// EngineConfig configures the 4-stage scanning engine.
type EngineConfig struct {
	UseNmap       bool
	Resolver      Resolver
	Fingerprinter *fingerprint.Fingerprinter
	NmapRunner    *NmapRunner
	Now           func() time.Time
	Calibrate     bool
	// UnstableHosts lists IPs previously seen active that should be re-probed in Stage 4 if missed.
	UnstableHosts []string
	// Optional test hooks for deterministic discovery/service scanning without network calls.
	CustomDiscoveryFn   func(ctx context.Context, ips []string) ([]string, error)
	CustomServiceScanFn func(ctx context.Context, activeIPs []string, ports []int) (map[string][]domain.ObservedService, string, error)

	// MaxChunkWorkers bounds concurrent chunk workers (each runs its own nmap process).
	// 0 = DefaultChunkWorkers() (DZIECIOL_CHUNK_WORKERS env or 4). Further bounded by profile
	// Concurrency, by MaxRatePPS/MinWorkerRatePPS and by the number of pending chunks.
	MaxChunkWorkers int
	// WindowPollInterval controls how often a running scan re-checks its time window so an
	// overrunning scan is stopped mid-chunk (default 1s).
	WindowPollInterval time.Duration
	// DisableAdaptiveChunking turns off in-run chunk re-sizing from measured throughput.
	DisableAdaptiveChunking bool
	// Screenshots captures landing pages of HTTP services (nil = no screenshots).
	Screenshots ScreenshotCapturer
}

// Engine runs, per ledger chunk, Stage 1 (host discovery: nmap sweep or TCP connect) with the
// Stage 4 re-probe of previously-seen hosts that went missing, then Stage 2 (nmap -sV) and
// Stage 3 (HTTP/HTTPS/TLS fingerprinting). Chunks move through the stages pipelined, under one
// rate budget, the Target Noise Governor and exact time-window pause/resume.
type Engine struct {
	cfg EngineConfig
}

// NewEngine creates a configured Engine instance.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if cfg.NmapRunner == nil {
		cfg.NmapRunner = NewNmapRunner(cfg.UseNmap)
	}
	if cfg.Fingerprinter == nil {
		cfg.Fingerprinter = fingerprint.New(fingerprint.DefaultOptions())
	}
	return &Engine{cfg: cfg}
}

// PrepareRun expands targets, filters exclusions, estimates chunks, and builds a ready ScanRun with Coverage Ledger.
func (e *Engine) PrepareRun(ctx context.Context, scanRunID string, profile domain.ScanProfile, exclusions []domain.TargetExclusion) (*domain.ScanRun, *TargetResolution, error) {
	wg, err := NewWindowGuard(profile.WindowEnabled, profile.WindowStart, profile.WindowEnd, profile.Timezone)
	if err != nil {
		return nil, nil, err
	}

	now := e.cfg.Now()
	est, resolution, err := EstimateTargets(ctx, EstimateRequest{
		Targets:               profile.Targets,
		Exclusions:            exclusions,
		Ports:                 profile.AllowedPorts,
		MaxRatePPS:            profile.MaxRatePPS,
		Concurrency:           profile.Concurrency,
		ChunkTargetSec:        profile.ChunkTargetSec,
		Window:                wg,
		Now:                   now,
		Resolver:              e.cfg.Resolver,
		EnableHTTPFingerprint: profile.EnableHTTPFingerprint,
	})
	if err != nil {
		return nil, nil, err
	}

	chunkSize := est.RecommendedChunkSize
	if e.cfg.Calibrate && len(resolution.IPs) > 0 {
		ports, _ := ParsePorts(EffectivePorts(profile.AllowedPorts, len(resolution.IPs)))
		cal := Calibrate(ctx, resolution.IPs, profile.ChunkTargetSec, profile.Concurrency, func(pctx context.Context, ip string) (bool, time.Duration) {
			t0 := time.Now()
			alive, _, _ := e.discoverStage(pctx, []string{ip}, ports, profile.MaxRatePPS, nil)
			return len(alive) > 0, time.Since(t0)
		})
		if cal.ChunkSize > 0 {
			chunkSize = cal.ChunkSize
		}
	}

	// Chunks sample the whole scope (ZMap-style cyclic-group permutation, see PermuteTargets),
	// so concurrent workers spread their probes over every subnet instead of each hammering
	// one contiguous block. The permutation is seeded by the run ID and the ledger stores
	// each chunk's targets, so resume/rescan sees exactly the same chunks.
	// Scopes of up to 4 /24s stay in order: there is no subnet load to spread, and contiguous
	// chunks keep nmap command lines compact (10.0.0.1-50).
	ordered := resolution.IPs
	if len(ordered) > PermuteMinTargets {
		h := fnv.New64a()
		_, _ = h.Write([]byte(scanRunID))
		ordered = PermuteTargets(ordered, h.Sum64())
	}
	chunks := BuildChunks(scanRunID, ordered, chunkSize)
	run := &domain.ScanRun{
		ID:          scanRunID,
		ProfileID:   profile.ID,
		Name:        profile.Name,
		RunType:     domain.ScanTypeActive,
		Status:      domain.ScanStatusQueued,
		TotalIPs:    len(resolution.IPs),
		TotalChunks: len(chunks),
		ETASeconds:  est.EstimatedSeconds,
		StartedAt:   now,
		Chunks:      chunks,
	}

	return run, resolution, nil
}

// speculativeHTTPTimeout bounds HTTP probes of services nmap did not identify.
const speculativeHTTPTimeout = 3 * time.Second

// debugHTTP (DZIECIOL_DEBUG_HTTP=1) logs every HTTP fingerprint error the Governor sees.
var debugHTTP = os.Getenv("DZIECIOL_DEBUG_HTTP") != ""

func (e *Engine) fingerprintStage(
	ctx context.Context,
	activeIPs []string,
	svcMap map[string][]domain.ObservedService,
	guessed map[string]bool,
	profile domain.ScanProfile,
	fpSem chan struct{},
	gov *Governor,
	ipToDomains map[string][]string,
	st *stageStats,
) {
	type fpJob struct {
		ip       string
		svcIndex int
		port     int
		domain   string
		scheme   string
	}

	var probeMu sync.Mutex
	e.protocolProbeStage(ctx, activeIPs, svcMap, guessed, gov, &probeMu, false)

	var jobs []fpJob
	for _, ip := range activeIPs {
		svcs := svcMap[ip]
		dom := ""
		if ds := ipToDomains[ip]; len(ds) > 0 {
			dom = ds[0]
		}
		for idx, s := range svcs {
			// Services nmap could only name from its port table (3001 "nessus") or not at all
			// ("tcpwrapped") get a speculative HTTP probe too: web apps on unusual ports.
			if !isHTTPServiceCandidate(s) && !(isUnidentified(s, guessed[ip+":"+strconv.Itoa(s.Port)]) && s.Banner == "") {
				continue
			}
			scheme := ""
			sn := strings.ToLower(s.ServiceName)
			if strings.Contains(sn, "https") || strings.Contains(sn, "ssl") || strings.Contains(sn, "tls") {
				scheme = "https"
			}
			jobs = append(jobs, fpJob{
				ip:       ip,
				svcIndex: idx,
				port:     s.Port,
				domain:   dom,
				scheme:   scheme,
			})
		}
	}
	if len(jobs) == 0 {
		e.protocolProbeStage(ctx, activeIPs, svcMap, guessed, gov, &probeMu, true)
		e.captureScreenshots(ctx, activeIPs, svcMap, profile, gov, st, &probeMu)
		return
	}
	st.httpServices.Add(int64(len(jobs)))

	// fpSem is shared by every chunk in flight, so HTTP concurrency is bounded scan-wide
	// (not per chunk); the request rate itself is bounded by the Governor.
	workers := cap(fpSem)
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	jobCh := make(chan fpJob, len(jobs))
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if ctx.Err() != nil {
					return
				}
				opts := fingerprint.DefaultOptions()
				if profile.UserAgent != "" {
					opts.UserAgent = profile.UserAgent
				}
				if job.scheme != "" {
					opts.Scheme = job.scheme
				}
				opts.RateLimiter = func(rctx context.Context, host string) error {
					st.httpRequests.Add(1)
					return gov.Wait(rctx, host)
				}
				// A service nmap could only name from the port table did not answer -sV's
				// HTTP probes: try it briefly, and don't read its silence as target distress
				// (on the /20 bench, winbox:8291 and Hikvision:8000 timeouts halved the global
				// HTTP rate four times, 150 -> 21 rps).
				speculative := guessed[job.ip+":"+strconv.Itoa(job.port)]
				if speculative {
					opts.Timeout = speculativeHTTPTimeout
				}
				opts.OnThrottle = func(host string, statusCode int, err error) {
					if debugHTTP && (statusCode > 0 || err != nil) {
						log.Printf("[DEBUG] http %s:%d speculative=%v status=%d err=%v", job.ip, job.port, speculative, statusCode, err)
					}
					if statusCode > 0 {
						gov.RecordHTTPStatus(host, statusCode)
					} else if err != nil && !speculative {
						classifyDialErr(gov, host, err)
					}
				}
				opts.Now = e.cfg.Now

				select {
				case fpSem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				fp, err := e.cfg.Fingerprinter.Probe(ctx, job.ip, job.port, job.domain, &opts)
				// Some servers accept TLS and plain HTTP on one port (Traefik entrypoints answer a
				// TLS hello with their default certificate and a 404); nmap then reports "https".
				// When HTTPS gives an error page or fails, also try plain HTTP and keep the
				// answer that is not an error.
				if job.scheme == "https" && job.port != 443 && ctx.Err() == nil && (err != nil || fp == nil || fp.StatusCode >= 400) {
					plain := opts
					plain.Scheme = "http"
					if fp2, err2 := e.cfg.Fingerprinter.Probe(ctx, job.ip, job.port, job.domain, &plain); err2 == nil && fp2 != nil && fp2.StatusCode > 0 && fp2.StatusCode < 400 {
						fp, err = fp2, nil
					}
				}
				<-fpSem
				if err == nil && fp != nil {
					gov.RecordSuccess(job.ip)
					mu.Lock()
					svc := &svcMap[job.ip][job.svcIndex]
					svc.HTTP = fp
					// A real HTTP answer beats nmap's port-table guess or "tcpwrapped".
					if (isUnidentified(*svc, speculative) || (svc.ServiceName == "https" && fp.Scheme == "http")) && fp.Scheme != "" {
						svc.ServiceName = fp.Scheme
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	e.protocolProbeStage(ctx, activeIPs, svcMap, guessed, gov, &mu, true)
	e.captureScreenshots(ctx, activeIPs, svcMap, profile, gov, st, &mu)
}

func isHTTPServiceCandidate(s domain.ObservedService) bool {
	sn := strings.ToLower(s.ServiceName)
	if strings.Contains(sn, "http") || strings.Contains(sn, "www") || strings.Contains(sn, "ssl") || strings.Contains(sn, "tls") {
		return true
	}
	switch s.Port {
	case 80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9443:
		return true
	}
	// Unknown services that did not emit a non-HTTP server-first banner (like SSH/SMTP/FTP)
	// may be HTTP/HTTPS running on a non-standard port.
	if (sn == "" || sn == "unknown") && s.Banner == "" {
		return true
	}
	return false
}
