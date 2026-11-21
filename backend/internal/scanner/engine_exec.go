package scanner

import (
	"context"
	"fmt"
	"log"
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

// DefaultChunkWorkers returns DZIECIOL_CHUNK_WORKERS (1..64) or 4.
func DefaultChunkWorkers() int {
	if v := strings.TrimSpace(os.Getenv("DZIECIOL_CHUNK_WORKERS")); v != "" {
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
	scopeIPs := run.TotalIPs
	if resolution != nil {
		scopeIPs = len(resolution.IPs)
	}
	ports, err := ParsePorts(EffectivePorts(profile.AllowedPorts, scopeIPs))
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

	// One honest global budget of maxRate probes/s, split into
	//   - httpShare: HTTP fingerprinting requests (1 request = 1 new TCP connection, the
	//     same unit nmap -sT counts), paced by the Governor;
	//   - nmapPool: shared by every concurrently running nmap process via rateBudget.
	// Without nmap (pure-Go fallback) everything goes through the Governor at maxRate.
	useNmap := e.cfg.NmapRunner != nil && e.cfg.NmapRunner.UseNmap && e.cfg.NmapRunner.NmapBinary != "" &&
		e.cfg.CustomDiscoveryFn == nil && e.cfg.CustomServiceScanFn == nil
	httpShare := 0
	if profile.EnableHTTPFingerprint {
		httpShare = maxRate / 10
		if httpShare < 1 {
			httpShare = 1
		}
	}
	nmapPool := maxRate - httpShare
	if nmapPool < 1 {
		nmapPool = 1
	}
	govRate := maxRate
	if useNmap && httpShare > 0 {
		govRate = httpShare
	}

	gov := NewGovernor(GovernorConfig{
		GlobalRatePerSec: float64(govRate),
		// A tenth of a second's worth of burst (default would be a full second): on the
		// Hetzner /18 run, HTTP bursts on top of fully paced nmap shares were the brief
		// 1572..1598/s peaks against the 1500 cap.
		GlobalBurst:       max(4, govRate/10),
		PerHostRatePerSec: httpRPS,
		MinRatePerSec:     math.Min(float64(govRate), math.Max(5, float64(govRate)*0.1)),
		OnThrottle: func(te ThrottleEvent) {
			log.Printf("[INFO] scan %s governor throttle: host=%s reason=%s rate %.1f -> %.1f (%d events)", run.ID, te.Host, te.Reason, te.OldRate, te.NewRate, te.ErrorCount)
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

	// Pipeline shape: `workers` discovery workers (one nmap sweep each), svcWorkers service
	// workers (-sV runs are wait-bound, so several run side by side on small shares), and a
	// global pool of `concurrency` HTTP fingerprint slots.
	// Discovery is planned on the pool minus one service share, so a -sV process can always
	// start even while every discovery worker holds its share (otherwise chunks waiting for
	// Stage 2 could never finish and the pipeline would stall).
	//
	// -sV is wait-bound (silent services, probe chains), so it needs many concurrent
	// processes on small shares rather than one big share: with a single 84 pps service share
	// left beside 4x316 pps of sweeps, -sV queued behind discovery (120-140 s per chunk on
	// the /20 bench). Reserve svcWorkers small shares (at most a quarter of the pool).
	planWorkers, _ := ChunkWorkerPlan(e.cfg.MaxChunkWorkers, profile.Concurrency, nmapPool, pendingCount)
	svcWorkers := 2 * planWorkers
	if svcWorkers > 16 {
		svcWorkers = 16
	}
	svcWant := nmapPool / 64
	if svcWant < MinWorkerRatePPS {
		svcWant = MinWorkerRatePPS
	}
	svcReserve := svcWorkers * svcWant
	if svcReserve > nmapPool/4 {
		svcReserve = nmapPool / 4
		svcWant = svcReserve / svcWorkers
	}
	if svcWant < 1 {
		svcWant, svcReserve = 1, svcWorkers
	}
	discPool := nmapPool - svcReserve
	if discPool < 1 {
		discPool = 1
	}
	workers, perWorkerRate := ChunkWorkerPlan(e.cfg.MaxChunkWorkers, profile.Concurrency, discPool, pendingCount)
	budget := newRateBudget(nmapPool)
	fpSem := make(chan struct{}, concurrency)
	emit("scan.workers", map[string]any{
		"chunk_workers":       workers,
		"service_workers":     svcWorkers,
		"per_worker_rate_pps": perWorkerRate,
		"service_rate_pps":    svcWant,
		"http_rate_rps":       httpShare,
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
	claim := func(worker, rate int) (int, []string, bool) {
		mu.Lock()
		defer mu.Unlock()
		if scanCtx.Err() != nil {
			return -1, nil, false
		}
		if !windowGuard.IsOpen(e.cfg.Now()) {
			// Stop dispatching. Chunks already in a later pipeline stage are interrupted by
			// the window poller (within WindowPollInterval), not here.
			windowClosed.Store(true)
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
			ch.MaxRatePPS = rate
			ch.Worker = worker
			if i > maxDispatched {
				maxDispatched = i
			}
			if cb.OnChunkUpdate != nil {
				cb.OnChunkUpdate(*ch)
			}
			emit("scan.chunk", map[string]any{
				"chunk_id": ch.ID, "chunk_index": ch.ChunkIndex, "status": ch.Status, "ip_count": ch.IPCount,
				"worker": worker, "max_rate_pps": rate,
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
		// Adaptive re-chunking from measured per-worker discovery throughput. Only the
		// discovery stage scales with chunk size; -sV and HTTP run pipelined and their latency
		// is set by the slowest service, so feeding whole-chunk time back here used to shrink
		// chunks (512 -> 96 IPs) and multiply that fixed latency.
		if ch.Status == domain.ChunkStatusDone && !e.cfg.DisableAdaptiveChunking {
			discMs := sm.Discovery
			if discMs <= 0 {
				discMs = durMs
			}
			hps := float64(ch.IPCount) / (float64(discMs) / 1000.0)
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

	// Pipeline: discovery workers -> svcCh -> service workers -> HTTP fingerprint goroutines
	// (bounded by fpSem). A chunk is checkpointed (finish) only when every stage is done, so
	// the ledger semantics are unchanged: an interrupted chunk goes back to PENDING whatever
	// stage it was in. inflight bounds how far discovery may run ahead of the later stages.
	// A waiting chunk costs a few KB, so discovery may run up to 32 chunks ahead of the
	// later stages: slow HTTP fingerprinting must not stall the rate-bound sweep (on the
	// Hetzner run a 3*workers bound idled every sweep while chunks queued for HTTP).
	inflight := make(chan struct{}, workers+svcWorkers+32)
	svcCh := make(chan *chunkWork, svcWorkers)
	complete := func(w *chunkWork, err error) {
		var obs []domain.ObservedHost
		if err == nil {
			obs = e.buildObserved(w, ipToDomains)
		}
		finish(w.idx, w.start, obs, w.xml, w.cmds, w.sm, err)
		<-inflight
	}
	minShare := perWorkerRate / 2
	if minShare < MinWorkerRatePPS {
		minShare = MinWorkerRatePPS
	}
	// throttled scales an nmap share by the Governor's distress factor, so explicit target
	// distress (HTTP 429/503, reset bursts) also slows every nmap process launched afterwards.
	// Timeouts deliberately don't: on the Hetzner /18 run, HTTP timeouts pushed the Governor
	// to its floor and, through this coupling, cut every sweep to 29 pps (10x slower).
	throttled := func(n int) int {
		if f := gov.DistressFactor(); f < 1 {
			n = int(float64(n) * f)
		}
		if n < 1 {
			n = 1
		}
		return n
	}
	// svcShare sizes a -sV process's share. While chunks are still being dispatched it takes
	// its small reserved share. Once every chunk is dispatched no new sweep will ask for
	// budget, so -sV (whose port phase is rate-bound) may wait for a large share: the final
	// chunks' -sV is the tail of the whole scan (100-150 s at 21 pps on the /20 bench).
	allDispatched := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return nextIdx >= len(run.Chunks)
	}
	svcShare := func() (int, int) {
		want := svcWant
		if allDispatched() {
			if tail := nmapPool / svcWorkers; tail > want {
				want = tail
			}
		}
		want = throttled(want)
		minGrant := want / 2
		if minGrant > MinWorkerRatePPS && !allDispatched() {
			minGrant = MinWorkerRatePPS
		}
		if minGrant < 1 {
			minGrant = 1
		}
		return want, minGrant
	}

	var discWG sync.WaitGroup
	for wk := 1; wk <= workers; wk++ {
		discWG.Add(1)
		go func(worker int) {
			defer discWG.Done()
			for {
				select {
				case inflight <- struct{}{}:
				case <-scanCtx.Done():
					return
				}
				rate, err := budget.acquire(scanCtx, throttled(perWorkerRate), min(minShare, throttled(perWorkerRate)))
				if err != nil {
					<-inflight
					return
				}
				i, targets, ok := claim(worker, rate)
				if !ok {
					budget.release(rate)
					<-inflight
					return
				}
				w := &chunkWork{idx: i, start: e.cfg.Now(), targets: targets}
				derr := e.discoverChunk(scanCtx, w, ports, rate, retryUnstable, gov, unstableSet, stats)
				budget.release(rate)
				if derr != nil || len(w.alive) == 0 {
					complete(w, derr)
					continue
				}
				select {
				case svcCh <- w:
				case <-scanCtx.Done():
					complete(w, scanCtx.Err())
				}
			}
		}(wk)
	}

	var svcWG, fpWG sync.WaitGroup
	for s := 0; s < svcWorkers; s++ {
		svcWG.Add(1)
		go func() {
			defer svcWG.Done()
			for w := range svcCh {
				if scanCtx.Err() != nil {
					complete(w, scanCtx.Err())
					continue
				}
				if err := e.serviceChunk(scanCtx, w, ports, budget, svcShare, gov, stats); err != nil {
					complete(w, err)
					continue
				}
				if !profile.EnableHTTPFingerprint {
					complete(w, nil)
					continue
				}
				fpWG.Add(1)
				go func(w *chunkWork) {
					defer fpWG.Done()
					t0 := time.Now()
					e.fingerprintStage(scanCtx, w.alive, w.svcMap, w.guessed, profile, fpSem, gov, ipToDomains, stats)
					d := time.Since(t0)
					stats.fingerprintNs.Add(int64(d))
					w.sm.Fingerprint += d.Milliseconds()
					complete(w, scanCtx.Err())
				}(w)
			}
		}()
	}
	discWG.Wait()
	close(svcCh)
	svcWG.Wait()
	fpWG.Wait()
	nmapPeak := budget.peakUsed()
	gs := gov.Stats()
	emit("scan.budget", map[string]any{"nmap_pool_pps": nmapPool, "nmap_peak_granted_pps": nmapPeak, "http_rate_rps": httpShare, "max_rate_pps": maxRate,
		"governor_rate": gs.CurrentRate, "governor_initial_rate": gs.InitialRate, "throttle_count": gs.ThrottleCount,
		"timeouts": gs.TimeoutCount, "http_429": gs.HTTP429Count, "rst": gs.RSTCount, "distress": gov.DistressFactor()})

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
