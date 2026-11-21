package scanner

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

const (
	// MinWorkerRatePPS is the smallest --max-rate share we hand to one nmap process.
	// Below that, splitting the budget further only adds process overhead.
	MinWorkerRatePPS    = 20
	defaultChunkWorkers = 4
	// interruptedByWindowMsg marks chunks cut mid-flight by a closing time window.
	interruptedByWindowMsg = "interrupted: scan window closed; chunk will be rescanned in the next window"
)

// DefaultChunkWorkers returns ASI_CHUNK_WORKERS (1..64) or 4.
func DefaultChunkWorkers() int {
	if v := strings.TrimSpace(os.Getenv("ASI_CHUNK_WORKERS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 64 {
			return n
		}
	}
	return defaultChunkWorkers
}

// ChunkWorkerPlan computes how many chunk workers to run and the per-process --max-rate
// so that workers*perWorkerRate <= maxRatePPS (the profile's hard global cap).
func ChunkWorkerPlan(maxWorkers, profileConcurrency, maxRatePPS, pendingChunks int) (workers, perWorkerRate int) {
	if maxRatePPS <= 0 {
		maxRatePPS = 300
	}
	w := maxWorkers
	if w <= 0 {
		w = DefaultChunkWorkers()
	}
	if profileConcurrency > 0 && w > profileConcurrency {
		w = profileConcurrency
	}
	if byRate := maxRatePPS / MinWorkerRatePPS; w > byRate {
		w = byRate
	}
	if pendingChunks > 0 && w > pendingChunks {
		w = pendingChunks
	}
	if w < 1 {
		w = 1
	}
	perWorkerRate = maxRatePPS / w
	if perWorkerRate < 1 {
		perWorkerRate = 1
	}
	return w, perWorkerRate
}

// Execute runs or resumes a ScanRun.
//
// Chunks (the Coverage Ledger) are processed by N concurrent chunk workers, each running its
// own nmap process. The profile's MaxRatePPS is a hard global cap: each process receives
// MaxRatePPS/N via --max-rate, so the sum over all concurrent processes never exceeds it.
// The pure-Go fallback and HTTP fingerprinting share a single global Governor.
//
// Time windows are enforced twice: before a chunk is dispatched, and continuously while
// chunks run (every WindowPollInterval). When the window closes mid-scan, in-flight nmap
// processes are killed, their chunks go back to PENDING, finished chunks stay DONE, and the
// run ends as PAUSED_WINDOW so it is resumed from that checkpoint in the next window.
//
// After every finished chunk the measured per-worker throughput re-tunes the size of the
// not-yet-dispatched tail of the ledger towards ChunkTargetSec seconds per chunk.
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
			cb.OnEvent(domain.LiveEvent{Type: evType, ScanRunID: run.ID, Timestamp: e.cfg.Now(), Payload: payload})
		}
	}

	maxRate := profile.MaxRatePPS
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
	chunkTargetSec := profile.ChunkTargetSec
	if chunkTargetSec <= 0 {
		chunkTargetSec = DefaultChunkTargetSec
	}

	gov := NewGovernor(GovernorConfig{
		GlobalRatePerSec:  float64(maxRate),
		PerHostRatePerSec: httpRPS,
		MinRatePerSec:     math.Max(5, float64(maxRate)*0.1),
		OnThrottle: func(te ThrottleEvent) {
			emit("governor.throttle", map[string]any{
				"host": te.Host, "reason": te.Reason, "old_rate": te.OldRate, "new_rate": te.NewRate, "error_count": te.ErrorCount,
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
	var segmentIPs []string

	// Wall-clock scanning time accumulated over previous window segments.
	baseDurMs := run.DurationMs
	pendingCount := 0
	for _, ch := range run.Chunks {
		if ch.Status != domain.ChunkStatusDone {
			pendingCount++
		} else if run.DurationMs <= 0 {
			baseDurMs += ch.DurationMs
		}
	}
	segStart := e.cfg.Now()

	workers, perWorkerRate := ChunkWorkerPlan(e.cfg.MaxChunkWorkers, profile.Concurrency, maxRate, pendingCount)
	fpWorkers := concurrency / workers
	if fpWorkers < 1 {
		fpWorkers = 1
	}
	emit("scan.workers", map[string]any{
		"chunk_workers":       workers,
		"per_worker_rate_pps": perWorkerRate,
		"max_rate_pps":        maxRate,
		"pending_chunks":      pendingCount,
	})

	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()
	var windowClosed atomic.Bool
	if windowGuard.Enabled {
		poll := e.cfg.WindowPollInterval
		if poll <= 0 {
			poll = time.Second
		}
		go func() {
			t := time.NewTicker(poll)
			defer t.Stop()
			for {
				select {
				case <-scanCtx.Done():
					return
				case <-t.C:
					if !windowGuard.IsOpen(e.cfg.Now()) {
						windowClosed.Store(true)
						cancelScan()
						return
					}
				}
			}
		}()
	}

	stats := &stageStats{}
	var mu sync.Mutex
	nextIdx := 0
	maxDispatched := -1
	var ewmaHPS float64

	progressLocked := func() {
		now := e.cfg.Now()
		run.DurationMs = baseDurMs + now.Sub(segStart).Milliseconds()
		if run.DurationMs > 0 {
			hps := float64(run.ScannedIPs) / (float64(run.DurationMs) / 1000.0)
			run.HostsPerSec = math.Round(hps*100) / 100
			remaining := run.TotalIPs - run.ScannedIPs
			if remaining < 0 {
				remaining = 0
			}
			if hps > 0 {
				run.ETASeconds = int64(math.Ceil(float64(remaining) / hps))
			}
		}
	}

	// claim hands the next not-yet-done chunk to a worker, or reports that dispatching must stop.
	claim := func(worker int) (int, []string, bool) {
		mu.Lock()
		defer mu.Unlock()
		if scanCtx.Err() != nil {
			return -1, nil, false
		}
		if !windowGuard.IsOpen(e.cfg.Now()) {
			windowClosed.Store(true)
			cancelScan()
			return -1, nil, false
		}
		for nextIdx < len(run.Chunks) {
			i := nextIdx
			nextIdx++
			ch := &run.Chunks[i]
			if ch.Status == domain.ChunkStatusDone {
				continue
			}
			start := e.cfg.Now()
			ch.Status = domain.ChunkStatusRunning
			ch.StartedAt = &start
			ch.FinishedAt = nil
			ch.Error = ""
			ch.NmapCommands = nil
			ch.MaxRatePPS = perWorkerRate
			ch.Worker = worker
			if i > maxDispatched {
				maxDispatched = i
			}
			if cb.OnChunkUpdate != nil {
				cb.OnChunkUpdate(*ch)
			}
			emit("scan.chunk", map[string]any{
				"chunk_id": ch.ID, "chunk_index": ch.ChunkIndex, "status": ch.Status, "ip_count": ch.IPCount,
				"worker": worker, "max_rate_pps": perWorkerRate,
			})
			return i, append([]string(nil), ch.Targets...), true
		}
		return -1, nil, false
	}

	finish := func(i int, chunkStart time.Time, obs []domain.ObservedHost, chunkXML string, cmds []string, sm chunkStageMs, chunkErr error) {
		mu.Lock()
		defer mu.Unlock()
		ch := &run.Chunks[i]
		ch.NmapCommands = cmds

		if chunkErr != nil && scanCtx.Err() != nil {
			// Interrupted mid-flight: by the closing window (rescan next window) or by the user.
			if ctx.Err() == nil && windowClosed.Load() {
				ch.Status = domain.ChunkStatusPending
				ch.StartedAt = nil
				ch.Error = interruptedByWindowMsg
			} else {
				ch.Status = domain.ChunkStatusPaused
			}
			if cb.OnChunkUpdate != nil {
				cb.OnChunkUpdate(*ch)
			}
			emit("scan.chunk", map[string]any{
				"chunk_id": ch.ID, "chunk_index": ch.ChunkIndex, "status": ch.Status, "error": ch.Error,
			})
			return
		}

		chunkEnd := e.cfg.Now()
		durMs := chunkEnd.Sub(chunkStart).Milliseconds()
		if durMs < 1 {
			durMs = 1
		}
		ch.FinishedAt = &chunkEnd
		ch.DurationMs = durMs
		if chunkErr != nil {
			ch.Status = domain.ChunkStatusFailed
			ch.Error = chunkErr.Error()
		} else {
			ch.Status = domain.ChunkStatusDone
			segmentIPs = append(segmentIPs, ch.Targets...)
		}
		if chunkXML != "" {
			xmlDocs = append(xmlDocs, chunkXML)
		}

		activeCount, svcCount := 0, 0
		for _, o := range obs {
			allObserved = append(allObserved, o)
			if o.IsAlive {
				activeCount++
				svcCount += len(o.Services)
			}
			if cb.OnHostObserved != nil {
				cb.OnHostObserved(o)
			}
		}
		ch.ActiveHosts = activeCount
		ch.Services = svcCount

		run.CompletedChunks++
		run.ScannedIPs += ch.IPCount
		run.ActiveHosts += activeCount
		run.ServicesFound += svcCount
		progressLocked()

		chunkSnapshot := *ch
		// Adaptive re-chunking from measured per-worker throughput.
		if ch.Status == domain.ChunkStatusDone && !e.cfg.DisableAdaptiveChunking {
			hps := float64(ch.IPCount) / (float64(durMs) / 1000.0)
			if ewmaHPS == 0 {
				ewmaHPS = hps
			} else {
				ewmaHPS = 0.5*ewmaHPS + 0.5*hps
			}
			if oldSize, newSize, ok := rechunkTail(run, maxDispatched+1, ewmaHPS, chunkTargetSec); ok {
				emit("scan.rechunk", map[string]any{
					"measured_hosts_per_sec_per_worker": math.Round(ewmaHPS*100) / 100,
					"old_chunk_size":                    oldSize,
					"new_chunk_size":                    newSize,
					"total_chunks":                      run.TotalChunks,
				})
			}
		}

		if cb.OnChunkUpdate != nil {
			cb.OnChunkUpdate(chunkSnapshot)
		}
		emit("scan.chunk", map[string]any{
			"chunk_id": chunkSnapshot.ID, "chunk_index": chunkSnapshot.ChunkIndex, "status": chunkSnapshot.Status,
			"active_hosts": chunkSnapshot.ActiveHosts, "services": chunkSnapshot.Services, "duration_ms": chunkSnapshot.DurationMs,
			"worker": chunkSnapshot.Worker, "nmap_commands": chunkSnapshot.NmapCommands,
			"stage_ms": sm,
		})
		emit("scan.progress", map[string]any{
			"scanned_ips": run.ScannedIPs, "total_ips": run.TotalIPs,
			"completed_chunks": run.CompletedChunks, "total_chunks": run.TotalChunks,
			"active_hosts": run.ActiveHosts, "services_found": run.ServicesFound,
			"hosts_per_sec": run.HostsPerSec, "eta_seconds": run.ETASeconds,
			"window_open": windowGuard.IsOpen(e.cfg.Now()), "chunk_workers": workers,
		})
		if cb.OnCheckpoint != nil {
			cb.OnCheckpoint(run)
		}
	}

	var wg sync.WaitGroup
	for w := 1; w <= workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				i, targets, ok := claim(worker)
				if !ok {
					return
				}
				chunkStart := e.cfg.Now()
				var sm chunkStageMs
				obs, chunkXML, cmds, chunkErr := e.executeChunk(scanCtx, targets, ports, profile, perWorkerRate, fpWorkers, retryUnstable, gov, unstableSet, ipToDomains, stats, &sm)
				finish(i, chunkStart, obs, chunkXML, cmds, sm, chunkErr)
			}
		}(w)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	mergedXML := MergeNmapXML(xmlDocs)
	run.RawNmapXML = mergedXML
	run.HasRawNmapXML = mergedXML != ""
	progressLocked()
	result := &RunResult{
		ScanRun:          run,
		ObservedHosts:    allObserved,
		RawNmapXML:       mergedXML,
		GovernorStats:    gov.Stats(),
		ScannedIPs:       segmentIPs,
		ChunkWorkers:     workers,
		PerWorkerRatePPS: perWorkerRate,
		StageTimings:     stats.snapshot(),
	}

	if err := ctx.Err(); err != nil {
		run.Status = domain.ScanStatusStopped
		for i := range run.Chunks {
			if run.Chunks[i].Status == domain.ChunkStatusRunning {
				run.Chunks[i].Status = domain.ChunkStatusPaused
			}
		}
		if cb.OnCheckpoint != nil {
			cb.OnCheckpoint(run)
		}
		return result, err
	}

	remaining, interrupted := 0, 0
	for _, ch := range run.Chunks {
		if ch.Status != domain.ChunkStatusDone && ch.Status != domain.ChunkStatusFailed {
			remaining++
			if ch.Error == interruptedByWindowMsg {
				interrupted++
			}
		}
	}
	if remaining > 0 {
		now := e.cfg.Now()
		run.Status = domain.ScanStatusPausedWindow
		run.WindowPausedCount++
		nextOpen := windowGuard.NextOpen(now)
		emit("scan.paused_window", map[string]any{
			"completed_chunks":   run.CompletedChunks,
			"total_chunks":       run.TotalChunks,
			"remaining_chunks":   remaining,
			"interrupted_chunks": interrupted,
			"next_window_open":   nextOpen.Format(time.RFC3339),
			"window_paused_cnt":  run.WindowPausedCount,
		})
		if cb.OnCheckpoint != nil {
			cb.OnCheckpoint(run)
		}
		result.PausedByWindow = true
		return result, nil
	}

	finished := e.cfg.Now()
	run.Status = domain.ScanStatusCompleted
	run.ETASeconds = 0
	run.FinishedAt = &finished
	emit("scan.completed", map[string]any{
		"total_ips": run.TotalIPs, "active_hosts": run.ActiveHosts, "services_found": run.ServicesFound,
		"duration_ms": run.DurationMs, "has_nmap_xml": run.HasRawNmapXML, "chunk_workers": workers,
		"stage_timings": stats.snapshot(),
	})
	if cb.OnCheckpoint != nil {
		cb.OnCheckpoint(run)
	}
	return result, nil
}

// rechunkTail re-splits the undispatched, untouched tail of the ledger (indices >= tailStart)
// when the measured per-worker throughput implies a chunk size at least 1.5x away from the
// current one. Returns the old and new chunk sizes when it re-chunked.
func rechunkTail(run *domain.ScanRun, tailStart int, hostsPerSec float64, chunkTargetSec int) (int, int, bool) {
	if tailStart < 0 || tailStart >= len(run.Chunks) || hostsPerSec <= 0 {
		return 0, 0, false
	}
	var tailIPs []string
	for i := tailStart; i < len(run.Chunks); i++ {
		ch := run.Chunks[i]
		if ch.Status != domain.ChunkStatusPending || ch.StartedAt != nil {
			return 0, 0, false
		}
		tailIPs = append(tailIPs, ch.Targets...)
	}
	if len(tailIPs) < 2*MinChunkSize {
		return 0, 0, false
	}
	cur := run.Chunks[tailStart].IPCount
	ideal := RecommendChunkSize(len(tailIPs), hostsPerSec, chunkTargetSec)
	if cur <= 0 || ideal <= 0 {
		return 0, 0, false
	}
	ratio := float64(ideal) / float64(cur)
	if ratio < 1.5 && ratio > 1/1.5 {
		return 0, 0, false
	}
	rebuilt := BuildChunks(run.ID, tailIPs, ideal)
	for k := range rebuilt {
		idx := tailStart + k
		rebuilt[k].ChunkIndex = idx
		rebuilt[k].ID = fmt.Sprintf("%s-chunk-%04d", run.ID, idx)
	}
	chunks := make([]domain.ScanChunk, 0, tailStart+len(rebuilt))
	chunks = append(chunks, run.Chunks[:tailStart]...)
	chunks = append(chunks, rebuilt...)
	run.Chunks = chunks
	run.TotalChunks = len(chunks)
	return cur, ideal, true
}

func (e *Engine) executeChunk(
	ctx context.Context,
	chunkIPs []string,
	ports []int,
	profile domain.ScanProfile,
	ratePPS int,
	fpWorkers int,
	retryUnstable int,
	gov *Governor,
	unstableSet map[string]struct{},
	ipToDomains map[string][]string,
	st *stageStats,
	sm *chunkStageMs,
) ([]domain.ObservedHost, string, []string, error) {
	var cmds []string
	record := func(c string) {
		if c != "" {
			cmds = append(cmds, c)
		}
	}
	stageStart := time.Now()
	endStage := func(acc *atomic.Int64, dst *int64) {
		d := time.Since(stageStart)
		acc.Add(int64(d))
		*dst += d.Milliseconds()
		stageStart = time.Now()
	}

	// Stage 1: Host Discovery.
	activeIPs, cmd, err := e.discoverStage(ctx, chunkIPs, ports, ratePPS, gov)
	record(cmd)
	endStage(&st.discoveryNs, &sm.Discovery)
	st.discoveryIPs.Add(int64(len(chunkIPs)))
	if err != nil {
		return nil, "", cmds, err
	}

	aliveSet := make(map[string]bool, len(activeIPs))
	for _, ip := range activeIPs {
		aliveSet[ip] = true
	}

	// Stage 4 (early verification): re-probe previously-seen hosts missed in Stage 1.
	var toReprobe []string
	for _, ip := range chunkIPs {
		if !aliveSet[ip] {
			if _, isTracked := unstableSet[ip]; isTracked {
				toReprobe = append(toReprobe, ip)
			}
		}
	}
	for attempt := 0; attempt < retryUnstable && len(toReprobe) > 0; attempt++ {
		if ctx.Err() != nil {
			return nil, "", cmds, ctx.Err()
		}
		recovered, rcmd, rerr := e.discoverStage(ctx, toReprobe, ports, ratePPS, gov)
		record(rcmd)
		if rerr != nil {
			if ctx.Err() != nil {
				return nil, "", cmds, ctx.Err()
			}
			break
		}
		recSet := make(map[string]bool, len(recovered))
		for _, ip := range recovered {
			recSet[ip] = true
			if !aliveSet[ip] {
				aliveSet[ip] = true
				activeIPs = append(activeIPs, ip)
			}
		}
		var stillMissing []string
		for _, ip := range toReprobe {
			if !recSet[ip] {
				stillMissing = append(stillMissing, ip)
			}
		}
		toReprobe = stillMissing
	}
	endStage(&st.reprobeNs, &sm.Reprobe)
	st.liveHosts.Add(int64(len(activeIPs)))

	// Stage 2: Service Detection strictly on active hosts & allowed ports.
	var svcMap map[string][]domain.ObservedService
	var chunkXML string
	if len(activeIPs) > 0 {
		var scmd string
		svcMap, chunkXML, scmd, err = e.serviceScanStage(ctx, activeIPs, ports, ratePPS, gov)
		record(scmd)
		if err != nil {
			return nil, "", cmds, err
		}
	}
	for _, svcs := range svcMap {
		st.openPorts.Add(int64(len(svcs)))
	}
	endStage(&st.serviceNs, &sm.Service)

	// Stage 3: Safe HTTP/HTTPS/TLS Fingerprinting with bounded worker pool.
	if profile.EnableHTTPFingerprint && len(activeIPs) > 0 {
		e.fingerprintStage(ctx, activeIPs, svcMap, profile, fpWorkers, gov, ipToDomains, st)
	}
	endStage(&st.fingerprintNs, &sm.Fingerprint)
	if ctx.Err() != nil {
		return nil, "", cmds, ctx.Err()
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
	return observed, chunkXML, cmds, nil
}

func (e *Engine) discoverStage(ctx context.Context, ips []string, ports []int, ratePPS int, gov *Governor) ([]string, string, error) {
	if e.cfg.CustomDiscoveryFn != nil {
		alive, err := e.cfg.CustomDiscoveryFn(ctx, ips)
		return alive, "", err
	}
	return e.cfg.NmapRunner.DiscoverHostsDetailed(ctx, ips, ports, ratePPS, gov)
}

func (e *Engine) serviceScanStage(ctx context.Context, activeIPs []string, ports []int, ratePPS int, gov *Governor) (map[string][]domain.ObservedService, string, string, error) {
	if e.cfg.CustomServiceScanFn != nil {
		m, x, err := e.cfg.CustomServiceScanFn(ctx, activeIPs, ports)
		return m, x, "", err
	}
	return e.cfg.NmapRunner.ScanServicesDetailed(ctx, activeIPs, ports, ratePPS, gov)
}
