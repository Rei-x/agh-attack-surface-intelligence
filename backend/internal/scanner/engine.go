package scanner

import (
	"context"
	"fmt"
	"math"
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
}

// Engine orchestrates Stage 1 (host discovery) -> Stage 2 (service detection)
// -> Stage 3 (HTTP/HTTPS fingerprinting) -> Stage 4 (unstable host verification re-probe)
// with bounded concurrency, Target Noise Governor, and exact time-window Pause/Resume.
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
		ports, _ := ParsePorts(profile.AllowedPorts)
		cal := Calibrate(ctx, resolution.IPs, profile.ChunkTargetSec, profile.Concurrency, func(pctx context.Context, ip string) (bool, time.Duration) {
			t0 := time.Now()
			alive, _ := e.discoverStage(pctx, []string{ip}, ports, profile.MaxRatePPS, nil)
			return len(alive) > 0, time.Since(t0)
		})
		if cal.ChunkSize > 0 {
			chunkSize = cal.ChunkSize
		}
	}

	chunks := BuildChunks(scanRunID, resolution.IPs, chunkSize)
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

// Execute runs or resumes a ScanRun across chunks, enforcing time windows cleanly at chunk boundaries.
func (e *Engine) Execute(ctx context.Context, run *domain.ScanRun, profile domain.ScanProfile, resolution *TargetResolution, cb RunCallbacks) (*RunResult, error) {
	if run == nil {
		return nil, fmt.Errorf("scan run is nil")
	}

	windowGuard, err := NewWindowGuard(profile.WindowEnabled, profile.WindowStart, profile.WindowEnd, profile.Timezone)
	if err != nil {
		return nil, err
	}

	ports, err := ParsePorts(profile.AllowedPorts)
	if err != nil {
		return nil, err
	}

	emit := func(evType string, payload map[string]any) {
		if cb.OnEvent != nil {
			cb.OnEvent(domain.LiveEvent{
				Type:      evType,
				ScanRunID: run.ID,
				Timestamp: e.cfg.Now(),
				Payload:   payload,
			})
		}
	}

	maxRate := float64(profile.MaxRatePPS)
	if maxRate <= 0 {
		maxRate = 300
	}
	httpRPS := float64(profile.HTTPRPS)
	if httpRPS <= 0 {
		httpRPS = 15
	}
	concurrency := profile.Concurrency
	if concurrency <= 0 {
		concurrency = 32
	}
	retryUnstable := profile.RetryUnstableCount
	if retryUnstable <= 0 {
		retryUnstable = 2
	}

	gov := NewGovernor(GovernorConfig{
		GlobalRatePerSec:  maxRate,
		PerHostRatePerSec: httpRPS,
		MinRatePerSec:     math.Max(5, maxRate*0.1),
		OnThrottle: func(te ThrottleEvent) {
			emit("governor.throttle", map[string]any{
				"host":        te.Host,
				"reason":      te.Reason,
				"old_rate":    te.OldRate,
				"new_rate":    te.NewRate,
				"error_count": te.ErrorCount,
			})
		},
	})

	unstableSet := make(map[string]struct{}, len(e.cfg.UnstableHosts))
	for _, ip := range e.cfg.UnstableHosts {
		unstableSet[ip] = struct{}{}
	}

	ipToDomains := map[string][]string{}
	if resolution != nil && resolution.IPToDomains != nil {
		ipToDomains = resolution.IPToDomains
	}

	run.Status = domain.ScanStatusRunning
	if run.StartedAt.IsZero() {
		run.StartedAt = e.cfg.Now()
	}

	var xmlDocs []string
	if run.RawNmapXML != "" {
		xmlDocs = append(xmlDocs, run.RawNmapXML)
	}
	var allObserved []domain.ObservedHost

	// Track already-completed chunks when resuming.
	var totalChunkMs int64
	for _, ch := range run.Chunks {
		if ch.Status == domain.ChunkStatusDone {
			totalChunkMs += ch.DurationMs
		}
	}

	for i := range run.Chunks {
		chunk := &run.Chunks[i]
		// Exact Resume: skip chunks already finished in prior window!
		if chunk.Status == domain.ChunkStatusDone {
			continue
		}

		// Check context cancellation before starting chunk.
		if err := ctx.Err(); err != nil {
			run.Status = domain.ScanStatusStopped
			chunk.Status = domain.ChunkStatusPaused
			mergedXML := MergeNmapXML(xmlDocs)
			run.RawNmapXML = mergedXML
			run.HasRawNmapXML = mergedXML != ""
			if cb.OnCheckpoint != nil {
				cb.OnCheckpoint(run)
			}
			return &RunResult{
				ScanRun:       run,
				ObservedHosts: allObserved,
				RawNmapXML:    mergedXML,
				GovernorStats: gov.Stats(),
			}, err
		}

		// Hard Time Window Gate at chunk boundary.
		now := e.cfg.Now()
		if !windowGuard.IsOpen(now) {
			run.Status = domain.ScanStatusPausedWindow
			run.WindowPausedCount++
			chunk.Status = domain.ChunkStatusPending
			nextOpen := windowGuard.NextOpen(now)
			mergedXML := MergeNmapXML(xmlDocs)
			run.RawNmapXML = mergedXML
			run.HasRawNmapXML = mergedXML != ""

			emit("scan.paused_window", map[string]any{
				"chunk_index":       chunk.ChunkIndex,
				"completed_chunks":  run.CompletedChunks,
				"total_chunks":      run.TotalChunks,
				"next_window_open":  nextOpen.Format(time.RFC3339),
				"window_paused_cnt": run.WindowPausedCount,
			})
			if cb.OnCheckpoint != nil {
				cb.OnCheckpoint(run)
			}
			return &RunResult{
				ScanRun:        run,
				ObservedHosts:  allObserved,
				RawNmapXML:     mergedXML,
				GovernorStats:  gov.Stats(),
				PausedByWindow: true,
			}, nil
		}

		// Execute chunk across the 4 stages.
		chunkStart := e.cfg.Now()
		chunk.Status = domain.ChunkStatusRunning
		chunk.StartedAt = &chunkStart
		chunk.Error = ""
		if cb.OnChunkUpdate != nil {
			cb.OnChunkUpdate(*chunk)
		}
		emit("scan.chunk", map[string]any{
			"chunk_id":    chunk.ID,
			"chunk_index": chunk.ChunkIndex,
			"status":      chunk.Status,
			"ip_count":    chunk.IPCount,
		})

		chunkObserved, chunkXML, chunkErr := e.executeChunk(ctx, chunk.Targets, ports, profile, concurrency, retryUnstable, gov, unstableSet, ipToDomains)
		if chunkErr != nil && ctx.Err() != nil {
			chunk.Status = domain.ChunkStatusPaused
			run.Status = domain.ScanStatusStopped
			mergedXML := MergeNmapXML(xmlDocs)
			run.RawNmapXML = mergedXML
			run.HasRawNmapXML = mergedXML != ""
			if cb.OnChunkUpdate != nil {
				cb.OnChunkUpdate(*chunk)
			}
			if cb.OnCheckpoint != nil {
				cb.OnCheckpoint(run)
			}
			return &RunResult{
				ScanRun:       run,
				ObservedHosts: allObserved,
				RawNmapXML:    mergedXML,
				GovernorStats: gov.Stats(),
			}, ctx.Err()
		}

		chunkEnd := e.cfg.Now()
		durMs := chunkEnd.Sub(chunkStart).Milliseconds()
		if durMs < 1 {
			durMs = 1
		}
		chunk.FinishedAt = &chunkEnd
		chunk.DurationMs = durMs
		totalChunkMs += durMs

		if chunkErr != nil {
			chunk.Status = domain.ChunkStatusFailed
			chunk.Error = chunkErr.Error()
		} else {
			chunk.Status = domain.ChunkStatusDone
		}

		if chunkXML != "" {
			xmlDocs = append(xmlDocs, chunkXML)
		}

		activeCount := 0
		svcCount := 0
		for _, obs := range chunkObserved {
			allObserved = append(allObserved, obs)
			if obs.IsAlive {
				activeCount++
				svcCount += len(obs.Services)
			}
			if cb.OnHostObserved != nil {
				cb.OnHostObserved(obs)
			}
		}

		chunk.ActiveHosts = activeCount
		chunk.Services = svcCount

		// Recompute run progress & ETA.
		run.CompletedChunks++
		run.ScannedIPs += chunk.IPCount
		run.ActiveHosts += activeCount
		run.ServicesFound += svcCount
		run.DurationMs = totalChunkMs

		if totalChunkMs > 0 {
			hps := float64(run.ScannedIPs) / (float64(totalChunkMs) / 1000.0)
			run.HostsPerSec = math.Round(hps*100) / 100
			remainingIPs := run.TotalIPs - run.ScannedIPs
			if remainingIPs < 0 {
				remainingIPs = 0
			}
			if hps > 0 {
				run.ETASeconds = int64(math.Ceil(float64(remainingIPs) / hps))
			}
		}

		if cb.OnChunkUpdate != nil {
			cb.OnChunkUpdate(*chunk)
		}
		emit("scan.chunk", map[string]any{
			"chunk_id":     chunk.ID,
			"chunk_index":  chunk.ChunkIndex,
			"status":       chunk.Status,
			"active_hosts": chunk.ActiveHosts,
			"services":     chunk.Services,
			"duration_ms":  chunk.DurationMs,
		})
		emit("scan.progress", map[string]any{
			"scanned_ips":      run.ScannedIPs,
			"total_ips":        run.TotalIPs,
			"completed_chunks": run.CompletedChunks,
			"total_chunks":     run.TotalChunks,
			"active_hosts":     run.ActiveHosts,
			"services_found":   run.ServicesFound,
			"hosts_per_sec":    run.HostsPerSec,
			"eta_seconds":      run.ETASeconds,
			"window_open":      windowGuard.IsOpen(e.cfg.Now()),
		})
		if cb.OnCheckpoint != nil {
			cb.OnCheckpoint(run)
		}
	}

	finished := e.cfg.Now()
	mergedXML := MergeNmapXML(xmlDocs)
	run.RawNmapXML = mergedXML
	run.HasRawNmapXML = mergedXML != ""
	run.Status = domain.ScanStatusCompleted
	run.ETASeconds = 0
	run.FinishedAt = &finished

	emit("scan.completed", map[string]any{
		"total_ips":      run.TotalIPs,
		"active_hosts":   run.ActiveHosts,
		"services_found": run.ServicesFound,
		"duration_ms":    run.DurationMs,
		"has_nmap_xml":   run.HasRawNmapXML,
	})
	if cb.OnCheckpoint != nil {
		cb.OnCheckpoint(run)
	}

	return &RunResult{
		ScanRun:       run,
		ObservedHosts: allObserved,
		RawNmapXML:    mergedXML,
		GovernorStats: gov.Stats(),
	}, nil
}

func (e *Engine) executeChunk(
	ctx context.Context,
	chunkIPs []string,
	ports []int,
	profile domain.ScanProfile,
	concurrency int,
	retryUnstable int,
	gov *Governor,
	unstableSet map[string]struct{},
	ipToDomains map[string][]string,
) ([]domain.ObservedHost, string, error) {
	// Stage 1: Host Discovery.
	activeIPs, err := e.discoverStage(ctx, chunkIPs, ports, profile.MaxRatePPS, gov)
	if err != nil {
		return nil, "", err
	}

	aliveSet := make(map[string]bool, len(activeIPs))
	for _, ip := range activeIPs {
		aliveSet[ip] = true
	}

	// Stage 4 (early verification): Unstable host verification re-probe for previously-seen hosts missed in Stage 1.
	var toReprobe []string
	for _, ip := range chunkIPs {
		if !aliveSet[ip] {
			if _, isTracked := unstableSet[ip]; isTracked {
				toReprobe = append(toReprobe, ip)
			}
		}
	}
	if len(toReprobe) > 0 && retryUnstable > 0 {
		for attempt := 0; attempt < retryUnstable && len(toReprobe) > 0; attempt++ {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			recovered, rerr := e.discoverStage(ctx, toReprobe, ports, profile.MaxRatePPS, gov)
			if rerr != nil {
				break
			}
			var stillMissing []string
			recSet := make(map[string]bool, len(recovered))
			for _, ip := range recovered {
				recSet[ip] = true
				if !aliveSet[ip] {
					aliveSet[ip] = true
					activeIPs = append(activeIPs, ip)
				}
			}
			for _, ip := range toReprobe {
				if !recSet[ip] {
					stillMissing = append(stillMissing, ip)
				}
			}
			toReprobe = stillMissing
		}
	}

	// Stage 2: Service Detection strictly on active hosts & allowed ports.
	var svcMap map[string][]domain.ObservedService
	var chunkXML string
	if len(activeIPs) > 0 {
		svcMap, chunkXML, err = e.serviceScanStage(ctx, activeIPs, ports, profile.MaxRatePPS, gov)
		if err != nil {
			return nil, "", err
		}
	}

	// Stage 3: Safe HTTP/HTTPS/TLS Fingerprinting with bounded worker pool.
	if profile.EnableHTTPFingerprint && len(activeIPs) > 0 {
		e.fingerprintStage(ctx, activeIPs, svcMap, profile, concurrency, gov, ipToDomains)
	}

	now := e.cfg.Now()
	observed := make([]domain.ObservedHost, 0, len(chunkIPs))
	for _, ip := range chunkIPs {
		domains := ipToDomains[ip]
		var hostname string
		if len(domains) > 0 {
			hostname = domains[0]
		}
		isAlive := aliveSet[ip]
		svcs := svcMap[ip]
		if len(svcs) > 0 {
			isAlive = true
		}
		observed = append(observed, domain.ObservedHost{
			IP:         ip,
			Hostname:   hostname,
			Domains:    append([]string(nil), domains...),
			IsAlive:    isAlive,
			ObservedAt: now,
			Services:   svcs,
		})
	}
	return observed, chunkXML, nil
}

func (e *Engine) discoverStage(ctx context.Context, ips []string, ports []int, maxRatePPS int, gov *Governor) ([]string, error) {
	if e.cfg.CustomDiscoveryFn != nil {
		return e.cfg.CustomDiscoveryFn(ctx, ips)
	}
	return e.cfg.NmapRunner.DiscoverHosts(ctx, ips, ports, maxRatePPS, gov)
}

func (e *Engine) serviceScanStage(ctx context.Context, activeIPs []string, ports []int, maxRatePPS int, gov *Governor) (map[string][]domain.ObservedService, string, error) {
	if e.cfg.CustomServiceScanFn != nil {
		return e.cfg.CustomServiceScanFn(ctx, activeIPs, ports)
	}
	return e.cfg.NmapRunner.ScanServices(ctx, activeIPs, ports, maxRatePPS, gov)
}

func (e *Engine) fingerprintStage(
	ctx context.Context,
	activeIPs []string,
	svcMap map[string][]domain.ObservedService,
	profile domain.ScanProfile,
	concurrency int,
	gov *Governor,
	ipToDomains map[string][]string,
) {
	type fpJob struct {
		ip       string
		svcIndex int
		port     int
		domain   string
		scheme   string
	}

	var jobs []fpJob
	for _, ip := range activeIPs {
		svcs := svcMap[ip]
		dom := ""
		if ds := ipToDomains[ip]; len(ds) > 0 {
			dom = ds[0]
		}
		for idx, s := range svcs {
			if !isHTTPServiceCandidate(s) {
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
		return
	}

	workers := concurrency
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers > 32 {
		workers = 32
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
					return gov.Wait(rctx, host)
				}
				opts.OnThrottle = func(host string, statusCode int, err error) {
					if statusCode > 0 {
						gov.RecordHTTPStatus(host, statusCode)
					} else if err != nil {
						classifyDialErr(gov, host, err)
					}
				}
				opts.Now = e.cfg.Now

				fp, err := e.cfg.Fingerprinter.Probe(ctx, job.ip, job.port, job.domain, &opts)
				if err == nil && fp != nil {
					gov.RecordSuccess(job.ip)
					mu.Lock()
					svcMap[job.ip][job.svcIndex].HTTP = fp
					if svcMap[job.ip][job.svcIndex].ServiceName == "" || svcMap[job.ip][job.svcIndex].ServiceName == "unknown" {
						svcMap[job.ip][job.svcIndex].ServiceName = fp.Scheme
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
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
