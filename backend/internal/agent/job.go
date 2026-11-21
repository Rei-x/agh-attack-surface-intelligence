package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/scanner"
)

// eventBuf collects engine events between progress uploads (bounded: oldest dropped).
type eventBuf struct {
	mu  sync.Mutex
	max int
	evs []domain.LiveEvent
}

func (b *eventBuf) add(ev domain.LiveEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.evs = append(b.evs, ev)
	if len(b.evs) > b.max {
		b.evs = b.evs[len(b.evs)-b.max:]
	}
}

func (b *eventBuf) take() []domain.LiveEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.evs
	b.evs = nil
	return out
}

func (b *eventBuf) putBack(evs []domain.LiveEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.evs = append(evs, b.evs...)
	if len(b.evs) > b.max {
		b.evs = b.evs[len(b.evs)-b.max:]
	}
}

// progressSnap is the latest checkpoint of the running engine.
type progressSnap struct {
	mu      sync.Mutex
	version int
	sent    int
	timing  agenthub.Timing
	chunks  []domain.ScanChunk
}

func (p *progressSnap) set(run *domain.ScanRun) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.version++
	p.timing = agenthub.Timing{DurationMs: run.DurationMs, HostsPerSec: run.HostsPerSec, ETASeconds: run.ETASeconds, WindowPausedCount: run.WindowPausedCount}
	p.chunks = append(p.chunks[:0:0], run.Chunks...)
}

// updateChunk records a chunk state change between checkpoints.
func (p *progressSnap) updateChunk(ch domain.ScanChunk) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.chunks {
		if p.chunks[i].ID == ch.ID {
			p.chunks[i] = ch
			p.version++
			return
		}
	}
}

func (p *progressSnap) get() (agenthub.Timing, []domain.ScanChunk, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	changed := p.version != p.sent
	p.sent = p.version
	return p.timing, p.chunks, changed
}

// outsideAllowlist returns the first IP not covered by the local allowlist ("" when all are
// allowed or no allowlist is configured).
func (a *Agent) outsideAllowlist(ips []string) string {
	if len(a.allow) == 0 {
		return ""
	}
	for _, s := range ips {
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return s
		}
		ip = ip.Unmap()
		ok := false
		for _, p := range a.allow {
			if p.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return s
		}
	}
	return ""
}

func (a *Agent) newEngine(unstable []string) *scanner.Engine {
	cfg := scanner.EngineConfig{UseNmap: scanner.NmapAvailable(), UnstableHosts: unstable}
	if a.cfg.EngineConfig != nil {
		cfg = a.cfg.EngineConfig(cfg)
	}
	return scanner.NewEngine(cfg)
}

// postRetry sends a small control call, retrying network failures until ctx ends.
func (a *Agent) postRetry(ctx context.Context, path string, in any, out *agenthub.ControlResponse) error {
	for attempt := 0; ; attempt++ {
		_, err := a.c.do(ctx, time.Minute, http.MethodPost, path, in, out)
		if err == nil || !retryable(err) || ctx.Err() != nil {
			return err
		}
		backoff(ctx, attempt)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// finishSegment queues the segment end in the durable outbox and waits until everything up
// to it is uploaded (on agent shutdown, it gets a short grace period; the rest is sent on
// the next start).
func (a *Agent) finishSegment(ctx context.Context, runID string, fin agenthub.FinishRequest) {
	fin.SegmentID = randomID()
	fin.Events = append(fin.Events, a.events.take()...)
	if err := a.box.put("finish", runID, fin); err != nil {
		a.logf("[ERROR] cannot buffer the end of run %s: %v", runID, err)
	}
	drainCtx := ctx
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		drainCtx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	_ = a.drainOutbox(drainCtx, true)
	a.logf("[INFO] run %s: segment finished (%s)", runID, fin.Outcome)
}

// runJob executes one job with the regular scanner engine and streams the results back.
func (a *Agent) runJob(ctx context.Context, spec *agenthub.JobSpec) {
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctl := &jobCtl{runID: spec.RunID, cancel: cancel}
	a.mu.Lock()
	a.cur = ctl
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.cur = nil
		a.mu.Unlock()
	}()
	a.events.take() // drop leftovers of a previous run

	profile := spec.Profile
	resumed := len(spec.Chunks) > 0
	a.logf("[INFO] job %s %q: targets=%v ports=%s rate=%dpps resumed=%v", spec.RunID, spec.RunName,
		profile.Targets, profile.AllowedPorts, profile.MaxRatePPS, resumed)

	run := &domain.ScanRun{
		ID: spec.RunID, ProfileID: profile.ID, Name: spec.RunName, RunType: domain.ScanTypeActive,
		Status: domain.ScanStatusRunning, TotalIPs: spec.Run.TotalIPs, TotalChunks: spec.Run.TotalChunks,
		ScannedIPs: spec.Run.ScannedIPs, CompletedChunks: spec.Run.CompletedChunks, ActiveHosts: spec.Run.ActiveHosts,
		ServicesFound: spec.Run.ServicesFound, DurationMs: spec.Run.DurationMs, WindowPausedCount: spec.Run.WindowPausedCount,
		StartedAt: spec.Run.StartedAt, Chunks: spec.Chunks,
	}
	engine := a.newEngine(spec.UnstableHosts)
	var resolution *scanner.TargetResolution

	if !resumed {
		prepared, res, err := engine.PrepareRun(jobCtx, spec.RunID, profile, spec.Exclusions)
		if err != nil {
			a.finishSegment(ctx, spec.RunID, agenthub.FinishRequest{Outcome: agenthub.OutcomeFailed, Error: "preparing scan: " + err.Error()})
			return
		}
		if prepared.TotalIPs == 0 {
			reason := "no addresses to scan"
			if res != nil {
				reason = fmt.Sprintf("no addresses to scan: %d excluded by the exclusion list, %d invalid entries (agent DNS)",
					res.ExcludedCount, len(res.InvalidEntries))
			}
			a.finishSegment(ctx, spec.RunID, agenthub.FinishRequest{Outcome: agenthub.OutcomeFailed, Error: reason})
			return
		}
		if bad := a.outsideAllowlist(res.IPs); bad != "" {
			a.logf("[WARN] REFUSING job %s: target %s is outside the local allowlist %v", spec.RunID, bad, a.caps.AllowCIDRs)
			a.finishSegment(ctx, spec.RunID, agenthub.FinishRequest{Outcome: agenthub.OutcomeRefused,
				Error: fmt.Sprintf("target %s is outside the agent's local allowlist (--allow-cidr %s)", bad, strings.Join(a.caps.AllowCIDRs, ","))})
			return
		}
		var resp agenthub.ControlResponse
		err = a.postRetry(jobCtx, "/api/v1/agent/jobs/"+spec.RunID+"/start", agenthub.StartRequest{
			TotalIPs: prepared.TotalIPs, ETASeconds: prepared.ETASeconds, Chunks: prepared.Chunks,
		}, &resp)
		if err != nil {
			if ctx.Err() == nil {
				a.logf("[WARN] job %s: start rejected: %v", spec.RunID, err)
			}
			return
		}
		if resp.Duplicate {
			return // the server already has a ledger for this run: claim it again to get it
		}
		if resp.Control != "" {
			a.finishSegment(ctx, spec.RunID, agenthub.FinishRequest{Outcome: controlOutcome(resp.Control), Chunks: prepared.Chunks})
			return
		}
		run.Chunks = prepared.Chunks
		run.TotalIPs, run.TotalChunks, run.ETASeconds = prepared.TotalIPs, prepared.TotalChunks, prepared.ETASeconds
		resolution = res
	} else {
		var ips []string
		for _, ch := range spec.Chunks {
			if ch.Status != domain.ChunkStatusDone && ch.Status != domain.ChunkStatusFailed {
				ips = append(ips, ch.Targets...)
			}
		}
		if bad := a.outsideAllowlist(ips); bad != "" {
			a.logf("[WARN] REFUSING job %s: chunk target %s is outside the local allowlist %v", spec.RunID, bad, a.caps.AllowCIDRs)
			a.finishSegment(ctx, spec.RunID, agenthub.FinishRequest{Outcome: agenthub.OutcomeRefused,
				Error: fmt.Sprintf("target %s is outside the agent's local allowlist (--allow-cidr %s)", bad, strings.Join(a.caps.AllowCIDRs, ","))})
			return
		}
		// Hostname -> IP mapping for HTTP Host headers, like a local resume.
		_, resolution, _ = scanner.EstimateTargets(jobCtx, scanner.EstimateRequest{
			Targets: profile.Targets, Exclusions: spec.Exclusions, Ports: profile.AllowedPorts,
		})
	}

	// Callbacks run under the engine's lock: they only buffer, never touch the network.
	var obsMu sync.Mutex
	var pending []domain.ObservedHost
	snap := &progressSnap{}
	snap.set(run)
	cb := scanner.RunCallbacks{
		OnEvent: a.events.add,
		OnHostObserved: func(o domain.ObservedHost) {
			obsMu.Lock()
			pending = append(pending, o)
			obsMu.Unlock()
			if o.IsAlive {
				a.events.add(hostDiscoveredEvent(spec.RunID, o))
			}
		},
		OnChunkUpdate: func(ch domain.ScanChunk) {
			if ch.Status != domain.ChunkStatusDone && ch.Status != domain.ChunkStatusFailed {
				snap.updateChunk(ch) // RUNNING / PAUSED shows up in the server's ledger
				return
			}
			obsMu.Lock()
			obs := pending
			pending = nil
			obsMu.Unlock()
			if obs == nil {
				obs = []domain.ObservedHost{}
			}
			if err := a.box.put("chunk", spec.RunID, agenthub.ChunkUpload{Chunk: ch, Observations: obs}); err != nil {
				a.logf("[ERROR] cannot buffer chunk %d of run %s: %v", ch.ChunkIndex, spec.RunID, err)
			}
		},
		OnCheckpoint: snap.set,
	}

	// Background senders: chunk results (durable outbox) and progress (best effort).
	var wg sync.WaitGroup
	sendCtx, stopSenders := context.WithCancel(jobCtx)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for sendCtx.Err() == nil {
			_ = a.drainOutbox(sendCtx, false)
			select {
			case <-sendCtx.Done():
			case <-a.box.notify:
			case <-time.After(5 * time.Second):
			}
		}
	}()
	go func() {
		defer wg.Done()
		t := time.NewTicker(a.cfg.ProgressEvery)
		defer t.Stop()
		for {
			select {
			case <-sendCtx.Done():
				return
			case <-t.C:
				a.sendProgress(sendCtx, ctl, snap)
			}
		}
	}()

	res, err := engine.Execute(jobCtx, run, profile, resolution, cb)
	stopSenders()
	wg.Wait()

	fin := agenthub.FinishRequest{
		Timing: agenthub.Timing{DurationMs: run.DurationMs, HostsPerSec: run.HostsPerSec, ETASeconds: run.ETASeconds, WindowPausedCount: run.WindowPausedCount},
		Chunks: run.Chunks,
	}
	if res != nil {
		fin.RawNmapXML = res.RawNmapXML
	}
	reason := ctl.why()
	switch {
	case err == nil && res != nil && res.PausedByWindow:
		fin.Outcome = agenthub.OutcomePausedWindow
	case err == nil:
		fin.Outcome = agenthub.OutcomeCompleted
	case reason == agenthub.ControlPause:
		fin.Outcome = agenthub.OutcomePausedUser
	case reason == agenthub.ControlStop:
		fin.Outcome = agenthub.OutcomeStopped
	case reason == "lost" || ctx.Err() != nil || errors.Is(err, context.Canceled):
		fin.Outcome = agenthub.OutcomeInterrupted
	default:
		fin.Outcome = agenthub.OutcomeFailed
		fin.Error = err.Error()
	}
	a.finishSegment(ctx, spec.RunID, fin)
}

func controlOutcome(control string) string {
	if control == agenthub.ControlPause {
		return agenthub.OutcomePausedUser
	}
	return agenthub.OutcomeStopped
}

func (a *Agent) sendProgress(ctx context.Context, ctl *jobCtl, snap *progressSnap) {
	timing, chunks, changed := snap.get()
	evs := a.events.take()
	if !changed && len(evs) == 0 {
		return
	}
	req := agenthub.ProgressRequest{Timing: timing, Events: evs}
	if changed {
		req.Chunks = chunks
	}
	var resp agenthub.ControlResponse
	_, err := a.c.do(ctx, 30*time.Second, http.MethodPost, "/api/v1/agent/jobs/"+ctl.runID+"/progress", req, &resp)
	if err != nil {
		switch statusOf(err) {
		case http.StatusNotFound, http.StatusForbidden, http.StatusConflict:
			a.logf("[WARN] run %s is no longer ours (%v); stopping it", ctl.runID, err)
			ctl.signal("lost")
		default:
			if len(evs) > 0 {
				a.events.putBack(evs)
			}
			snap.mu.Lock()
			snap.sent = -1 // resend the ledger next time
			snap.mu.Unlock()
		}
		return
	}
	a.applyControl(ctl.runID, resp.Control)
}

func hostDiscoveredEvent(runID string, obs domain.ObservedHost) domain.LiveEvent {
	ports := make([]int, 0, len(obs.Services))
	titles := make([]string, 0, len(obs.Services))
	for _, s := range obs.Services {
		ports = append(ports, s.Port)
		if s.HTTP != nil && s.HTTP.Title != "" {
			titles = append(titles, s.HTTP.Title)
		}
	}
	return domain.LiveEvent{
		Type: "scan.host_discovered", ScanRunID: runID, Timestamp: time.Now().UTC(),
		Payload: map[string]any{"ip": obs.IP, "hostname": obs.Hostname, "ports": ports, "services": len(obs.Services), "titles": titles},
	}
}
